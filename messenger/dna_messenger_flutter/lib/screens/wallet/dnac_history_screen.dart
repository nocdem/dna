// DNAC History Screen - Transaction history list
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import 'package:intl/intl.dart';
import '../../ffi/dna_engine.dart';
import '../../providers/dnac_provider.dart';
import '../../l10n/app_localizations.dart';

class DnacHistoryScreen extends ConsumerWidget {
  const DnacHistoryScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = AppLocalizations.of(context);
    final historyAsync = ref.watch(dnacHistoryProvider);

    return Scaffold(
      appBar: AppBar(
        title: Text(l10n.dnacHistoryTitle),
        actions: [
          IconButton(
            icon: const FaIcon(FontAwesomeIcons.arrowsRotate, size: 18),
            onPressed: () => ref.read(dnacHistoryProvider.notifier).refresh(),
            tooltip: l10n.dnacSync,
          ),
        ],
      ),
      body: historyAsync.when(
        data: (history) {
          if (history.isEmpty) {
            return Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  FaIcon(FontAwesomeIcons.clockRotateLeft,
                      size: 48,
                      color: Theme.of(context)
                          .colorScheme
                          .primary
                          .withAlpha(80)),
                  const SizedBox(height: 16),
                  Text(l10n.dnacNoTransactions,
                      style: Theme.of(context).textTheme.bodyLarge),
                ],
              ),
            );
          }

          return RefreshIndicator(
            onRefresh: () =>
                ref.read(dnacHistoryProvider.notifier).refresh(),
            child: ListView.builder(
              itemCount: history.length,
              itemBuilder: (context, index) =>
                  _HistoryTile(tx: history[index]),
            ),
          );
        },
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (e, _) => Center(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(l10n.dnacSyncFailed,
                  style: Theme.of(context).textTheme.bodyLarge),
              const SizedBox(height: 12),
              ElevatedButton.icon(
                onPressed: () =>
                    ref.read(dnacHistoryProvider.notifier).refresh(),
                icon: const FaIcon(FontAwesomeIcons.arrowsRotate, size: 14),
                label: Text(l10n.dnacSync),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _HistoryTile extends StatelessWidget {
  final DnacTxHistory tx;

  const _HistoryTile({required this.tx});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final l10n = AppLocalizations.of(context);

    final isGenesis = tx.type == 0;
    final isBurn = tx.type == 2;
    final isPositive = tx.amountDelta >= 0;

    final IconData icon;
    final Color color;
    final String typeLabel;

    if (isGenesis) {
      icon = FontAwesomeIcons.seedling;
      color = Colors.purple;
      typeLabel = l10n.dnacHistoryGenesis;
    } else if (isBurn) {
      icon = FontAwesomeIcons.fire;
      color = Colors.orange;
      typeLabel = l10n.dnacHistoryBurn;
    } else if (isPositive) {
      icon = FontAwesomeIcons.arrowDown;
      color = Colors.green;
      typeLabel = l10n.dnacHistoryReceived;
    } else {
      icon = FontAwesomeIcons.arrowUp;
      color = Colors.red;
      typeLabel = l10n.dnacHistorySent;
    }

    // Sign derived from actual amount_delta, not hardcoded
    final sign = isPositive ? '+' : '-';

    final dateStr = DateFormat.MMMd().add_Hm().format(tx.timestamp);
    final cpLen = tx.counterparty.length;
    final counterparty = cpLen > 0
        ? '${tx.counterparty.substring(0, cpLen < 12 ? cpLen : 12)}...'
        : '';

    return ListTile(
      onTap: () => showModalBottomSheet(
        context: context,
        isScrollControlled: true,
        backgroundColor: Colors.transparent,
        builder: (_) => _DnacTxDetailSheet(tx: tx),
      ),
      leading: Container(
        width: 40,
        height: 40,
        decoration: BoxDecoration(
          color: color.withAlpha(25),
          shape: BoxShape.circle,
        ),
        child: Center(child: FaIcon(icon, size: 16, color: color)),
      ),
      title: Row(
        children: [
          Text(typeLabel, style: theme.textTheme.bodyMedium),
          if (counterparty.isNotEmpty) ...[
            const SizedBox(width: 4),
            Expanded(
              child: Text(counterparty,
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurface.withAlpha(120),
                  ),
                  overflow: TextOverflow.ellipsis),
            ),
          ],
        ],
      ),
      subtitle: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(dateStr, style: theme.textTheme.bodySmall),
          if (tx.memo.isNotEmpty)
            Text(tx.memo,
                style: theme.textTheme.bodySmall?.copyWith(
                  fontStyle: FontStyle.italic,
                ),
                maxLines: 1,
                overflow: TextOverflow.ellipsis),
        ],
      ),
      trailing: Text(
        '$sign${tx.amountFormatted}',
        style: theme.textTheme.titleSmall?.copyWith(
          color: color,
          fontWeight: FontWeight.bold,
        ),
      ),
    );
  }
}

String _hexEncode(Uint8List bytes) {
  final sb = StringBuffer();
  for (final b in bytes) {
    sb.write(b.toRadixString(16).padLeft(2, '0'));
  }
  return sb.toString();
}

String _shortenMiddle(String s, {int head = 10, int tail = 8}) {
  if (s.length <= head + tail + 3) return s;
  return '${s.substring(0, head)}...${s.substring(s.length - tail)}';
}

class _DnacTxDetailSheet extends StatelessWidget {
  final DnacTxHistory tx;

  const _DnacTxDetailSheet({required this.tx});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final l10n = AppLocalizations.of(context);

    final isGenesis = tx.type == 0;
    final isBurn = tx.type == 2;
    final isReceived = !isGenesis && !isBurn && tx.amountDelta > 0;
    final isSent = !isGenesis && !isBurn && tx.amountDelta < 0;

    final LinearGradient headerGradient;
    final String typeLabel;
    if (isGenesis) {
      headerGradient = const LinearGradient(
        begin: Alignment.topCenter,
        end: Alignment.bottomCenter,
        colors: [Color(0xFF9C27B0), Color(0xFF6A1B9A)],
      );
      typeLabel = l10n.dnacHistoryGenesis;
    } else if (isBurn) {
      headerGradient = const LinearGradient(
        begin: Alignment.topCenter,
        end: Alignment.bottomCenter,
        colors: [Color(0xFFE8871E), Color(0xFFD45B0A)],
      );
      typeLabel = l10n.dnacHistoryBurn;
    } else if (isReceived) {
      headerGradient = const LinearGradient(
        begin: Alignment.topCenter,
        end: Alignment.bottomCenter,
        colors: [Color(0xFF00B87A), Color(0xFF00875A)],
      );
      typeLabel = l10n.dnacHistoryReceived;
    } else {
      headerGradient = const LinearGradient(
        begin: Alignment.topCenter,
        end: Alignment.bottomCenter,
        colors: [Color(0xFF1E88E5), Color(0xFF1565C0)],
      );
      typeLabel = l10n.dnacHistorySent;
    }

    final sign = tx.amountDelta >= 0 ? '+' : '-';
    final symbol = tx.isNative ? 'DNAC' : 'TOKEN';
    final txHashHex = _hexEncode(tx.txHash);
    final dateStr = DateFormat.yMMMd().add_Hms().format(tx.timestamp);

    return Container(
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        borderRadius: const BorderRadius.vertical(top: Radius.circular(24)),
      ),
      child: SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              margin: const EdgeInsets.only(top: 8),
              width: 40,
              height: 4,
              decoration: BoxDecoration(
                color: theme.dividerColor,
                borderRadius: BorderRadius.circular(2),
              ),
            ),
            Container(
              width: double.infinity,
              margin: const EdgeInsets.all(16),
              padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 28),
              decoration: BoxDecoration(
                gradient: headerGradient,
                borderRadius: BorderRadius.circular(20),
              ),
              child: Column(
                children: [
                  Text(
                    '$sign${tx.amountFormatted} $symbol',
                    style: const TextStyle(
                      color: Colors.white,
                      fontSize: 32,
                      fontWeight: FontWeight.w800,
                      letterSpacing: -0.5,
                    ),
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 8),
                  Text(
                    typeLabel,
                    style: TextStyle(
                      color: Colors.white.withValues(alpha: 0.85),
                      fontSize: 15,
                      fontWeight: FontWeight.w500,
                    ),
                    textAlign: TextAlign.center,
                  ),
                ],
              ),
            ),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              child: Column(
                children: [
                  if (tx.counterparty.isNotEmpty) ...[
                    _DetailRow(
                      icon: FontAwesomeIcons.user,
                      label: isReceived ? l10n.txDetailFrom : l10n.txDetailTo,
                      value: _shortenMiddle(tx.counterparty),
                      monospace: true,
                      onTap: () => _copyAndNotify(
                          context, tx.counterparty, l10n.txDetailAddressCopied),
                    ),
                    const Divider(height: 1),
                  ],
                  _DetailRow(
                    icon: FontAwesomeIcons.hashtag,
                    label: l10n.txDetailTransactionHash,
                    value: _shortenMiddle(txHashHex),
                    monospace: true,
                    onTap: () => _copyAndNotify(
                        context, txHashHex, l10n.txDetailHashCopied),
                  ),
                  const Divider(height: 1),
                  _DetailRow(
                    icon: FontAwesomeIcons.clock,
                    label: l10n.txDetailTime,
                    value: dateStr,
                  ),
                  if (isSent && tx.fee > 0) ...[
                    const Divider(height: 1),
                    _DetailRow(
                      icon: FontAwesomeIcons.coins,
                      label: 'Fee',
                      value: '${tx.feeFormatted} $symbol',
                    ),
                  ],
                  if (tx.memo.isNotEmpty) ...[
                    const Divider(height: 1),
                    _DetailRow(
                      icon: FontAwesomeIcons.noteSticky,
                      label: 'Memo',
                      value: tx.memo,
                    ),
                  ],
                ],
              ),
            ),
            const SizedBox(height: 24),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              child: SizedBox(
                width: double.infinity,
                child: TextButton(
                  onPressed: () => Navigator.pop(context),
                  child: Text(l10n.txDetailClose),
                ),
              ),
            ),
            const SizedBox(height: 16),
          ],
        ),
      ),
    );
  }

  void _copyAndNotify(BuildContext context, String text, String message) {
    Clipboard.setData(ClipboardData(text: text));
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
        duration: const Duration(seconds: 2),
        behavior: SnackBarBehavior.floating,
      ),
    );
  }
}

class _DetailRow extends StatelessWidget {
  final IconData icon;
  final String label;
  final String value;
  final bool monospace;
  final VoidCallback? onTap;

  const _DetailRow({
    required this.icon,
    required this.label,
    required this.value,
    this.monospace = false,
    this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(8),
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 14),
        child: Row(
          children: [
            FaIcon(icon, size: 14, color: theme.colorScheme.primary),
            const SizedBox(width: 16),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    label,
                    style: theme.textTheme.labelSmall?.copyWith(
                      color: theme.colorScheme.outline,
                    ),
                  ),
                  const SizedBox(height: 2),
                  Text(
                    value,
                    style: theme.textTheme.bodyMedium?.copyWith(
                      fontFamily: monospace ? 'monospace' : null,
                    ),
                  ),
                ],
              ),
            ),
            if (onTap != null)
              FaIcon(FontAwesomeIcons.copy,
                  size: 12, color: theme.colorScheme.outline),
          ],
        ),
      ),
    );
  }
}
