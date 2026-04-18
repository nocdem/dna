// Validator Control Screen — operator-only panel (Phase 16 Task 76).
//
// Visibility: only rendered when [myValidatorProvider] resolves to a
// non-null DnacValidator (the current identity has an active validator
// record). The gate is enforced at the callsite — this widget itself
// assumes the caller is a validator.
//
// Non-technical naming (per CLAUDE.md Flutter UI rule) is kept where
// possible, but the operator panel is inherently more technical — a user
// who can run a validator already knows the term. "Earner settings" is
// used for the panel title.

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';

import '../ffi/dnac_bindings.dart';
import '../l10n/app_localizations.dart';
import '../providers/stake_provider.dart';
import '../utils/logger.dart' as logger;

class ValidatorControlScreen extends ConsumerStatefulWidget {
  const ValidatorControlScreen({super.key});

  @override
  ConsumerState<ValidatorControlScreen> createState() =>
      _ValidatorControlScreenState();
}

class _ValidatorControlScreenState
    extends ConsumerState<ValidatorControlScreen> {
  final _commissionController = TextEditingController();
  bool _submitting = false;

  // Phase 14 does not expose the witness block height; we pass a
  // sentinel valid_before / signed_at anchor. The witness enforces
  // a DNAC_SIGN_FRESHNESS_WINDOW on signed_at_block, so this is a
  // known limitation until the RPC ships.
  // TODO(phase17): replace with real block height once the RPC ships.
  static const int _signedAtSentinel = 0x7fffffffffffffff;

  @override
  void dispose() {
    _commissionController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    final me = ref.watch(myValidatorProvider);
    if (me == null) {
      return Scaffold(
        appBar: AppBar(title: Text(l10n.validatorPanelTitle)),
        body: Center(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Text(
              l10n.validatorPanelNotValidator,
              textAlign: TextAlign.center,
            ),
          ),
        ),
      );
    }

    return Scaffold(
      appBar: AppBar(title: Text(l10n.validatorPanelTitle)),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            _StatusCard(me: me),
            const SizedBox(height: 20),
            _SectionHeader(title: l10n.validatorCommissionSection),
            Text(
              l10n.validatorCommissionHelp,
              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                    color: Theme.of(context)
                        .colorScheme
                        .onSurface
                        .withAlpha(160),
                  ),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _commissionController,
              keyboardType:
                  const TextInputType.numberWithOptions(decimal: true),
              inputFormatters: [
                FilteringTextInputFormatter.allow(RegExp(r'[0-9.]')),
              ],
              decoration: InputDecoration(
                labelText: l10n.validatorNewCommissionLabel,
                suffixText: '%',
                border: const OutlineInputBorder(),
                helperText: l10n.validatorCommissionRange,
              ),
            ),
            const SizedBox(height: 12),
            ElevatedButton.icon(
              onPressed: _submitting ? null : _onUpdateCommission,
              icon: const FaIcon(FontAwesomeIcons.floppyDisk, size: 14),
              label: Text(
                _submitting
                    ? l10n.delegationSubmitting
                    : l10n.validatorUpdateCommissionButton,
              ),
            ),
            const SizedBox(height: 32),
            _SectionHeader(title: l10n.validatorUnstakeSection),
            Text(l10n.validatorUnstakeWarning,
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                      color: Theme.of(context).colorScheme.error,
                    )),
            const SizedBox(height: 12),
            OutlinedButton.icon(
              style: OutlinedButton.styleFrom(
                foregroundColor: Theme.of(context).colorScheme.error,
              ),
              onPressed: _submitting ? null : _onUnstake,
              icon: const FaIcon(FontAwesomeIcons.powerOff, size: 14),
              label: Text(l10n.validatorUnstakeButton),
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _onUpdateCommission() async {
    final l10n = AppLocalizations.of(context);
    final raw = _commissionController.text.trim();
    if (raw.isEmpty) return;
    final pct = double.tryParse(raw);
    if (pct == null || pct < 0 || pct > 100) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(l10n.validatorCommissionInvalid)),
      );
      return;
    }
    final bps = (pct * 100).round();

    setState(() => _submitting = true);
    try {
      await ref.read(stakeActionsProvider).validatorUpdate(
            newCommissionBps: bps,
            signedAtBlock: _signedAtSentinel,
          );
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(l10n.validatorUpdateSuccess)),
      );
    } catch (e) {
      logger.logError('STAKE', 'validator_update failed: $e');
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(l10n.validatorUpdateFailed)),
      );
    } finally {
      if (mounted) setState(() => _submitting = false);
    }
  }

  Future<void> _onUnstake() async {
    final l10n = AppLocalizations.of(context);
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(l10n.validatorUnstakeConfirmTitle),
        content: Text(l10n.validatorUnstakeConfirmBody),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: Text(l10n.cancel),
          ),
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(true),
            style: TextButton.styleFrom(
              foregroundColor: Theme.of(context).colorScheme.error,
            ),
            child: Text(l10n.validatorUnstakeConfirmAction),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    if (!mounted) return;

    setState(() => _submitting = true);
    try {
      await ref.read(stakeActionsProvider).unstake();
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(l10n.validatorUnstakeSuccess)),
      );
      Navigator.of(context).pop();
    } catch (e) {
      logger.logError('STAKE', 'unstake failed: $e');
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(l10n.validatorUnstakeFailed)),
      );
    } finally {
      if (mounted) setState(() => _submitting = false);
    }
  }
}

class _StatusCard extends StatelessWidget {
  const _StatusCard({required this.me});
  final DnacValidator me;

  static const int _rawPerDnac = 100000000;

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    final theme = Theme.of(context);
    final selfDnac = me.selfStake / _rawPerDnac;
    final delegatedDnac = me.totalDelegated / _rawPerDnac;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const FaIcon(FontAwesomeIcons.crown, size: 18),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    l10n.validatorStatusLabel(me.shortId),
                    style: theme.textTheme.titleSmall,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            _KV(label: l10n.validatorFieldSelfStake,
                value: '${selfDnac.toStringAsFixed(2)} DNAC'),
            _KV(label: l10n.validatorFieldDelegated,
                value: '${delegatedDnac.toStringAsFixed(2)} DNAC'),
            _KV(label: l10n.validatorFieldCommission,
                value: '${me.commissionPct.toStringAsFixed(2)}%'),
          ],
        ),
      ),
    );
  }
}

class _KV extends StatelessWidget {
  const _KV({required this.label, required this.value});
  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Row(
        children: [
          SizedBox(
            width: 140,
            child: Text(label,
                style: theme.textTheme.bodySmall?.copyWith(
                  color: theme.colorScheme.onSurface.withAlpha(160),
                )),
          ),
          Expanded(
            child: Text(value,
                style: theme.textTheme.bodyMedium?.copyWith(
                  fontWeight: FontWeight.w600,
                )),
          ),
        ],
      ),
    );
  }
}

class _SectionHeader extends StatelessWidget {
  const _SectionHeader({required this.title});
  final String title;
  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Text(
        title,
        style: Theme.of(context).textTheme.titleSmall?.copyWith(
              fontWeight: FontWeight.bold,
            ),
      ),
    );
  }
}
