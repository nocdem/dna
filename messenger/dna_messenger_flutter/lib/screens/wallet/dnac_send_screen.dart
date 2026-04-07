// DNAC Send Screen - Send digital cash payment
import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../../ffi/dna_engine.dart';
import '../../providers/dnac_provider.dart';
import '../../providers/contacts_provider.dart';
import '../../providers/engine_provider.dart';
import '../../design_system/design_system.dart';
import '../../l10n/app_localizations.dart';
import '../../utils/logger.dart' as logger;

class DnacSendScreen extends ConsumerStatefulWidget {
  const DnacSendScreen({super.key});

  @override
  ConsumerState<DnacSendScreen> createState() => _DnacSendScreenState();
}

class _DnacSendScreenState extends ConsumerState<DnacSendScreen> {
  final _recipientController = TextEditingController();
  final _amountController = TextEditingController();
  final _memoController = TextEditingController();
  bool _isSending = false;
  int? _estimatedFee;
  bool _isEstimatingFee = false;
  Timer? _feeDebounce;

  @override
  void dispose() {
    _recipientController.dispose();
    _amountController.dispose();
    _memoController.dispose();
    _feeDebounce?.cancel();
    super.dispose();
  }

  void _onAmountChanged(String value) {
    _feeDebounce?.cancel();
    _feeDebounce = Timer(const Duration(milliseconds: 500), () {
      _estimateFee();
    });
  }

  Future<void> _estimateFee() async {
    final amountText = _amountController.text.trim();
    if (amountText.isEmpty) {
      setState(() {
        _estimatedFee = null;
        _isEstimatingFee = false;
      });
      return;
    }

    int rawAmount;
    try {
      rawAmount = parseDnacAmount(amountText);
    } catch (_) {
      setState(() {
        _estimatedFee = null;
        _isEstimatingFee = false;
      });
      return;
    }

    if (rawAmount <= 0) return;

    setState(() => _isEstimatingFee = true);

    try {
      final engine = await ref.read(engineProvider.future);
      final fee = await engine.dnacEstimateFee(rawAmount);
      if (mounted) {
        setState(() {
          _estimatedFee = fee;
          _isEstimatingFee = false;
        });
      }
    } catch (e) {
      logger.logError('DNAC', 'Fee estimate failed: $e');
      if (mounted) {
        setState(() {
          _estimatedFee = null;
          _isEstimatingFee = false;
        });
      }
    }
  }

  Future<void> _send() async {
    final l10n = AppLocalizations.of(context);
    final recipient = _recipientController.text.trim();
    final amountText = _amountController.text.trim();
    final memo = _memoController.text.trim();

    if (recipient.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(l10n.dnacInvalidRecipient)),
      );
      return;
    }

    int rawAmount;
    try {
      rawAmount = parseDnacAmount(amountText);
    } catch (_) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(l10n.dnacInvalidAmount)),
      );
      return;
    }

    if (rawAmount <= 0) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(l10n.dnacInvalidAmount)),
      );
      return;
    }

    // Check balance (include fee)
    final balance = ref.read(dnacBalanceProvider).valueOrNull;
    final totalCost = rawAmount + (_estimatedFee ?? 0);
    if (balance != null && totalCost > balance.confirmed) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(l10n.dnacInsufficientFunds)),
      );
      return;
    }

    // Confirmation dialog
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(l10n.dnacConfirmSend),
        content: Text(l10n.dnacAmountWithToken(formatDnacAmount(rawAmount))),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: Text(MaterialLocalizations.of(ctx).cancelButtonLabel),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: Text(l10n.dnacSend),
          ),
        ],
      ),
    );
    if (confirmed != true) return;

    setState(() => _isSending = true);

    try {
      await ref.read(dnacBalanceProvider.notifier).sendPayment(
        recipientFingerprint: recipient,
        amount: rawAmount,
        memo: memo.isNotEmpty ? memo : null,
      );

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(l10n.dnacSendSuccess)),
        );
        Navigator.pop(context);
      }
    } catch (e) {
      logger.logError('DNAC', 'Send failed: $e');
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('${l10n.dnacSendFailed}: $e')),
        );
      }
    } finally {
      if (mounted) setState(() => _isSending = false);
    }
  }

  void _pickContact() async {
    final contacts = ref.read(contactsProvider).valueOrNull ?? [];
    if (contacts.isEmpty) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(AppLocalizations.of(context).contactsEmpty)),
        );
      }
      return;
    }

    final result = await showModalBottomSheet<String>(
      context: context,
      builder: (context) {
        final l10n = AppLocalizations.of(context);
        return Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Padding(
              padding: const EdgeInsets.all(16),
              child: Text(l10n.dnacPickContact,
                  style: Theme.of(context).textTheme.titleMedium),
            ),
            Flexible(
              child: ListView.builder(
                shrinkWrap: true,
                itemCount: contacts.length,
                itemBuilder: (context, index) {
                  final contact = contacts[index];
                  return ListTile(
                    leading: const FaIcon(FontAwesomeIcons.user, size: 20),
                    title: Text(contact.effectiveName),
                    subtitle: Text(
                      '${contact.fingerprint.substring(0, 16)}...',
                      style: Theme.of(context).textTheme.bodySmall,
                    ),
                    onTap: () => Navigator.pop(context, contact.fingerprint),
                  );
                },
              ),
            ),
          ],
        );
      },
    );

    if (result != null && mounted) {
      _recipientController.text = result;
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final l10n = AppLocalizations.of(context);

    return Scaffold(
      appBar: AppBar(
        title: Text(l10n.dnacSendTitle),
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // Recipient
            TextField(
              controller: _recipientController,
              decoration: InputDecoration(
                labelText: l10n.dnacRecipient,
                hintText: l10n.dnacRecipientHint,
                prefixIcon: const Padding(
                  padding: EdgeInsets.all(12),
                  child: FaIcon(FontAwesomeIcons.user, size: 18),
                ),
                suffixIcon: IconButton(
                  icon: const FaIcon(FontAwesomeIcons.addressBook, size: 18),
                  onPressed: _pickContact,
                  tooltip: l10n.dnacPickContact,
                ),
                border: const OutlineInputBorder(),
              ),
              style: const TextStyle(fontSize: 14),
            ),
            const SizedBox(height: 16),

            // Amount
            TextField(
              controller: _amountController,
              decoration: InputDecoration(
                labelText: l10n.dnacAmount,
                hintText: l10n.dnacAmountHint,
                prefixIcon: const Padding(
                  padding: EdgeInsets.all(12),
                  child: FaIcon(FontAwesomeIcons.coins, size: 18),
                ),
                suffixText: l10n.dnacToken,
                border: const OutlineInputBorder(),
              ),
              keyboardType:
                  const TextInputType.numberWithOptions(decimal: true),
              onChanged: _onAmountChanged,
            ),
            const SizedBox(height: 16),

            // Memo
            TextField(
              controller: _memoController,
              decoration: InputDecoration(
                labelText: l10n.dnacMemo,
                hintText: l10n.dnacMemoHint,
                prefixIcon: const Padding(
                  padding: EdgeInsets.all(12),
                  child: FaIcon(FontAwesomeIcons.noteSticky, size: 18),
                ),
                border: const OutlineInputBorder(),
              ),
              maxLength: 255,
            ),
            const SizedBox(height: 16),

            // Fee estimate
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: theme.colorScheme.surfaceContainerHighest,
                borderRadius: BorderRadius.circular(12),
              ),
              child: Column(
                children: [
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Text(l10n.dnacFee,
                          style: theme.textTheme.bodyMedium),
                      if (_isEstimatingFee)
                        Text(l10n.dnacEstimatingFee,
                            style: theme.textTheme.bodySmall)
                      else if (_estimatedFee != null)
                        Text(
                          l10n.dnacAmountWithToken(
                              formatDnacAmount(_estimatedFee!)),
                          style: theme.textTheme.bodyMedium,
                        )
                      else
                        Text('—', style: theme.textTheme.bodyMedium),
                    ],
                  ),
                  if (_estimatedFee != null &&
                      _amountController.text.isNotEmpty) ...[
                    const Divider(height: 16),
                    Builder(builder: (context) {
                      int? rawAmount;
                      try {
                        rawAmount =
                            parseDnacAmount(_amountController.text.trim());
                      } catch (_) {}
                      if (rawAmount == null) return const SizedBox.shrink();
                      return Row(
                        mainAxisAlignment: MainAxisAlignment.spaceBetween,
                        children: [
                          Text(l10n.dnacTotal,
                              style: theme.textTheme.titleSmall?.copyWith(
                                fontWeight: FontWeight.bold,
                              )),
                          Text(
                            l10n.dnacAmountWithToken(formatDnacAmount(
                              rawAmount + _estimatedFee!,
                            )),
                            style: theme.textTheme.titleSmall?.copyWith(
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ],
                      );
                    }),
                  ],
                ],
              ),
            ),
            const SizedBox(height: 24),

            // Send button
            SizedBox(
              height: 48,
              child: ElevatedButton.icon(
                onPressed: _isSending ? null : _send,
                icon: _isSending
                    ? const SizedBox(
                        width: 18,
                        height: 18,
                        child:
                            CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const FaIcon(FontAwesomeIcons.paperPlane, size: 18),
                label: Text(
                    _isSending ? l10n.dnacSending : l10n.dnacConfirmSend),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
