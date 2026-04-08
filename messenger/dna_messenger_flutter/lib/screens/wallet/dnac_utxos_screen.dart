// DNAC UTXOs Screen - Coin details (advanced view)
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import 'package:intl/intl.dart';
import '../../ffi/dna_engine.dart';
import '../../providers/dnac_provider.dart';
import '../../l10n/app_localizations.dart';

class DnacUtxosScreen extends ConsumerWidget {
  const DnacUtxosScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = AppLocalizations.of(context);
    final utxosAsync = ref.watch(dnacUtxosProvider);

    return Scaffold(
      appBar: AppBar(
        title: Text(l10n.dnacUtxosTitle),
        actions: [
          IconButton(
            icon: const FaIcon(FontAwesomeIcons.arrowsRotate, size: 18),
            onPressed: () => ref.read(dnacUtxosProvider.notifier).refresh(),
            tooltip: l10n.dnacSync,
          ),
        ],
      ),
      body: utxosAsync.when(
        data: (utxos) {
          if (utxos.isEmpty) {
            return Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  FaIcon(FontAwesomeIcons.layerGroup,
                      size: 48,
                      color: Theme.of(context)
                          .colorScheme
                          .primary
                          .withAlpha(80)),
                  const SizedBox(height: 16),
                  Text(l10n.dnacNoUtxos,
                      style: Theme.of(context).textTheme.bodyLarge),
                ],
              ),
            );
          }

          return RefreshIndicator(
            onRefresh: () => ref.read(dnacUtxosProvider.notifier).refresh(),
            child: ListView.builder(
              itemCount: utxos.length,
              itemBuilder: (context, index) =>
                  _UtxoTile(utxo: utxos[index]),
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
                    ref.read(dnacUtxosProvider.notifier).refresh(),
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

class _UtxoTile extends StatelessWidget {
  final DnacUtxo utxo;

  const _UtxoTile({required this.utxo});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final l10n = AppLocalizations.of(context);

    final String statusLabel;
    final Color statusColor;
    final IconData statusIcon;

    switch (utxo.status) {
      case 0:
        statusLabel = l10n.dnacUtxoUnspent;
        statusColor = Colors.green;
        statusIcon = FontAwesomeIcons.circleCheck;
        break;
      case 1:
        statusLabel = l10n.dnacUtxoPending;
        statusColor = Colors.orange;
        statusIcon = FontAwesomeIcons.clock;
        break;
      default:
        statusLabel = l10n.dnacUtxoSpent;
        statusColor = Colors.grey;
        statusIcon = FontAwesomeIcons.circleXmark;
    }

    final dateStr = DateFormat.MMMd().add_Hm().format(utxo.receivedAt);
    final txPrefix = utxo.txHash
        .take(8)
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join();

    return ListTile(
      leading: Container(
        width: 40,
        height: 40,
        decoration: BoxDecoration(
          color: statusColor.withAlpha(25),
          shape: BoxShape.circle,
        ),
        child: Center(
            child: FaIcon(statusIcon, size: 16, color: statusColor)),
      ),
      title: Text(
        l10n.dnacAmountWithToken(utxo.amountFormatted),
        style: theme.textTheme.bodyMedium?.copyWith(
          fontWeight: FontWeight.bold,
        ),
      ),
      subtitle: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(dateStr, style: theme.textTheme.bodySmall),
          Text('$txPrefix...#${utxo.outputIndex}',
              style: theme.textTheme.bodySmall?.copyWith(
                fontFamily: 'monospace',
                fontSize: 11,
                color: theme.colorScheme.onSurface.withAlpha(100),
              )),
        ],
      ),
      trailing: Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
        decoration: BoxDecoration(
          color: statusColor.withAlpha(25),
          borderRadius: BorderRadius.circular(8),
        ),
        child: Text(statusLabel,
            style: theme.textTheme.bodySmall?.copyWith(
              color: statusColor,
              fontWeight: FontWeight.w500,
            )),
      ),
    );
  }
}
