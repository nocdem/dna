// Delegation Screen — "Support this earner" flow (Phase 16 Task 74).
//
// Non-technical UX: hides "delegate" / "stake" jargon.
// - Title: "Support {earner_name}"
// - Button: "Support this earner" (delegate)
// - Secondary button: "Stop supporting" (undelegate)
// - Help text: "Minimum 100 DNAC" / "About 10 minute hold before you
//   can stop supporting again" (hides "1-epoch hold").

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';

import '../ffi/dnac_bindings.dart';
import '../l10n/app_localizations.dart';
import '../providers/engine_provider.dart';
import '../providers/stake_provider.dart';
import '../utils/logger.dart' as logger;

class DelegationScreen extends ConsumerStatefulWidget {
  const DelegationScreen({super.key, required this.earner});
  final DnacValidator earner;

  @override
  ConsumerState<DelegationScreen> createState() => _DelegationScreenState();
}

class _DelegationScreenState extends ConsumerState<DelegationScreen> {
  static const int _rawPerDnac = 100000000;
  static const int _minDelegationRaw = 100 * _rawPerDnac; // 100 DNAC

  final _formKey = GlobalKey<FormState>();
  final _amountController = TextEditingController();
  bool _submitting = false;

  /// Fingerprint of widget.earner.pubkey, computed once via FFI. Used to
  /// cross-reference myDelegationsProvider entries. Empty until the first
  /// build-time resolve — falls back to empty-match if the FFI helper
  /// fails (non-fatal; UI just hides the "Your delegation" row).
  String _earnerFp = '';

  @override
  void initState() {
    super.initState();
    // Resolve fp lazily after first frame so we can access the engine
    // provider. engineProvider returns a Future so we defer via micro-task.
    WidgetsBinding.instance.addPostFrameCallback((_) async {
      try {
        final engine = await ref.read(engineProvider.future);
        final fp = engine.pubkeyToFingerprint(widget.earner.pubkey);
        if (mounted) setState(() => _earnerFp = fp);
      } catch (e) {
        logger.logError('STAKE', 'earner fp compute failed: $e');
      }
    });
  }

  @override
  void dispose() {
    _amountController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    final earner = widget.earner;
    final totalDnac = earner.totalStakeRaw / _rawPerDnac;

    // Look up our own delegation to THIS validator. Null means either we
    // have none OR the fp hasn't resolved yet (first paint before FFI).
    final delegations =
        ref.watch(myDelegationsProvider).valueOrNull ?? const <DnacDelegation>[];
    DnacDelegation? myDelegation;
    if (_earnerFp.isNotEmpty) {
      for (final d in delegations) {
        if (d.validatorFp == _earnerFp) {
          myDelegation = d;
          break;
        }
      }
    }

    return Scaffold(
      appBar: AppBar(
        title: Text(l10n.delegationTitle(earner.shortId)),
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        const FaIcon(FontAwesomeIcons.seedling, size: 18),
                        const SizedBox(width: 10),
                        Text(l10n.delegationEarnerLabel(earner.shortId),
                            style: Theme.of(context).textTheme.titleSmall),
                      ],
                    ),
                    const SizedBox(height: 10),
                    Text(l10n.stakeEarnerCommission(
                        earner.commissionPct.toStringAsFixed(2))),
                    const SizedBox(height: 4),
                    Text(l10n.stakeEarnerTotalLocked(
                        totalDnac.toStringAsFixed(2))),
                    if (myDelegation != null) ...[
                      const SizedBox(height: 8),
                      Text(
                        l10n.delegationYourAmount(
                            (myDelegation.amountRaw / _rawPerDnac)
                                .toStringAsFixed(2)),
                        style: TextStyle(
                          color: Colors.green.shade700,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ],
                  ],
                ),
              ),
            ),
            const SizedBox(height: 16),
            Form(
              key: _formKey,
              child: TextFormField(
                controller: _amountController,
                keyboardType:
                    const TextInputType.numberWithOptions(decimal: true),
                inputFormatters: [
                  FilteringTextInputFormatter.allow(RegExp(r'[0-9.]')),
                ],
                decoration: InputDecoration(
                  labelText: l10n.delegationAmountLabel,
                  helperText: l10n.delegationAmountHelper,
                  suffixText: 'DNAC',
                  border: const OutlineInputBorder(),
                ),
                validator: (value) {
                  if (value == null || value.trim().isEmpty) {
                    return l10n.delegationAmountRequired;
                  }
                  final parsed = double.tryParse(value);
                  if (parsed == null || parsed <= 0) {
                    return l10n.delegationAmountInvalid;
                  }
                  if (parsed < 100) {
                    return l10n.delegationAmountTooSmall;
                  }
                  return null;
                },
              ),
            ),
            const SizedBox(height: 12),
            _InfoTile(
              icon: FontAwesomeIcons.clock,
              text: l10n.delegationHoldInfo,
            ),
            _InfoTile(
              icon: FontAwesomeIcons.gift,
              text: l10n.delegationRewardInfo,
            ),
            const SizedBox(height: 20),
            ElevatedButton.icon(
              onPressed: _submitting ? null : _onSupport,
              icon: const FaIcon(FontAwesomeIcons.heart, size: 16),
              label: Text(_submitting
                  ? l10n.delegationSubmitting
                  : l10n.delegationSupportButton),
            ),
            const SizedBox(height: 8),
            OutlinedButton.icon(
              onPressed: _submitting ? null : _onStopSupporting,
              icon: const FaIcon(FontAwesomeIcons.heartCrack, size: 16),
              label: Text(l10n.delegationStopButton),
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _onSupport() async {
    if (!(_formKey.currentState?.validate() ?? false)) return;
    final dnac = double.parse(_amountController.text);
    final amountRaw = (dnac * _rawPerDnac).toInt();
    if (amountRaw < _minDelegationRaw) return;

    setState(() => _submitting = true);
    final l10n = AppLocalizations.of(context);
    try {
      await ref.read(stakeActionsProvider).delegate(
            validatorPubkey: widget.earner.pubkey,
            amountRaw: amountRaw,
          );
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(l10n.delegationSupportSuccess)),
      );
      Navigator.of(context).pop();
    } catch (e) {
      logger.logError('STAKE', 'delegate failed: $e');
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(l10n.delegationSupportFailed)),
      );
    } finally {
      if (mounted) setState(() => _submitting = false);
    }
  }

  Future<void> _onStopSupporting() async {
    final l10n = AppLocalizations.of(context);
    // Pre-fill the dialog with the user's current delegation amount (if
    // known) so they don't have to re-type it. One-shot read — snapshot
    // at dialog open time is fine.
    final delegations = ref.read(myDelegationsProvider).valueOrNull ??
        const <DnacDelegation>[];
    double? prefillDnac;
    if (_earnerFp.isNotEmpty) {
      for (final d in delegations) {
        if (d.validatorFp == _earnerFp) {
          prefillDnac = d.amountRaw / _rawPerDnac;
          break;
        }
      }
    }

    // Prompt for amount to withdraw.
    final amountDnac = await showDialog<double>(
      context: context,
      builder: (dialogCtx) => _UndelegateAmountDialog(
        earnerShortId: widget.earner.shortId,
        prefillDnac: prefillDnac,
      ),
    );
    if (amountDnac == null || amountDnac <= 0) return;
    final amountRaw = (amountDnac * _rawPerDnac).toInt();
    if (!mounted) return;

    setState(() => _submitting = true);
    try {
      await ref.read(stakeActionsProvider).undelegate(
            validatorPubkey: widget.earner.pubkey,
            amountRaw: amountRaw,
          );
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(l10n.delegationStopSuccess)),
      );
      Navigator.of(context).pop();
    } catch (e) {
      logger.logError('STAKE', 'undelegate failed: $e');
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(l10n.delegationStopFailed)),
      );
    } finally {
      if (mounted) setState(() => _submitting = false);
    }
  }
}

class _InfoTile extends StatelessWidget {
  const _InfoTile({required this.icon, required this.text});
  final IconData icon;
  final String text;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          FaIcon(icon, size: 14, color: theme.colorScheme.primary),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              text,
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.onSurface.withAlpha(180),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _UndelegateAmountDialog extends StatefulWidget {
  const _UndelegateAmountDialog({
    required this.earnerShortId,
    this.prefillDnac,
  });
  final String earnerShortId;

  /// When non-null, pre-populates the amount field with the user's current
  /// delegation so they don't have to re-type it. Still editable — users
  /// may want partial withdrawals.
  final double? prefillDnac;

  @override
  State<_UndelegateAmountDialog> createState() =>
      _UndelegateAmountDialogState();
}

class _UndelegateAmountDialogState extends State<_UndelegateAmountDialog> {
  late final TextEditingController _controller = TextEditingController(
    text: widget.prefillDnac != null
        ? widget.prefillDnac!.toStringAsFixed(2)
        : '',
  );

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    return AlertDialog(
      title: Text(l10n.delegationStopDialogTitle(widget.earnerShortId)),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(l10n.delegationStopDialogBody),
          const SizedBox(height: 12),
          TextField(
            controller: _controller,
            keyboardType:
                const TextInputType.numberWithOptions(decimal: true),
            inputFormatters: [
              FilteringTextInputFormatter.allow(RegExp(r'[0-9.]')),
            ],
            decoration: InputDecoration(
              labelText: l10n.delegationAmountLabel,
              suffixText: 'DNAC',
              border: const OutlineInputBorder(),
            ),
          ),
        ],
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(null),
          child: Text(l10n.cancel),
        ),
        ElevatedButton(
          onPressed: () {
            final parsed = double.tryParse(_controller.text);
            if (parsed == null || parsed <= 0) {
              Navigator.of(context).pop(null);
              return;
            }
            Navigator.of(context).pop(parsed);
          },
          child: Text(l10n.delegationStopButton),
        ),
      ],
    );
  }
}
