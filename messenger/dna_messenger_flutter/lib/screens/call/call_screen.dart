// Call Screen — full-screen PQ VoIP call UI (Faz A).
//
// Shows the current call: incoming (answer/decline), outgoing ("Calling…"),
// or connected. Voice/video is Faz B; for now "Connected" means the secure
// channel is established. Driven entirely by callProvider.

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';

import '../../l10n/app_localizations.dart';
import '../../providers/call_provider.dart';
import '../../providers/name_resolver_provider.dart';

class CallScreen extends ConsumerWidget {
  const CallScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final session = ref.watch(callProvider);
    final l10n = AppLocalizations.of(context);
    final theme = Theme.of(context);

    // Nothing to show — the overlay host renders this only when a call exists,
    // but guard anyway.
    if (session == null) return const SizedBox.shrink();

    final name = lazyResolveFingerprint(ref, session.peerFingerprint) ??
        _shortFp(session.peerFingerprint);
    final initial = name.isNotEmpty ? name.characters.first.toUpperCase() : '?';

    final status = switch (session.phase) {
      CallPhase.incoming => l10n.callIncoming,
      CallPhase.outgoing => l10n.callCalling,
      CallPhase.active => l10n.callConnected,
      CallPhase.ended => l10n.callEnded,
    };

    return Scaffold(
      backgroundColor: theme.colorScheme.surface,
      body: SafeArea(
        child: Column(
          children: [
            const Spacer(flex: 2),
            // Identity block — the single focal point.
            Text(
              status,
              style: theme.textTheme.titleMedium?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
                letterSpacing: 0.5,
              ),
            ),
            const SizedBox(height: 28),
            CircleAvatar(
              radius: 56,
              backgroundColor: theme.colorScheme.primaryContainer,
              child: Text(
                initial,
                style: theme.textTheme.displaySmall?.copyWith(
                  color: theme.colorScheme.onPrimaryContainer,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ),
            const SizedBox(height: 20),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 32),
              child: Text(
                name,
                textAlign: TextAlign.center,
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
                style: theme.textTheme.headlineSmall?.copyWith(
                  fontWeight: FontWeight.w600,
                ),
              ),
            ),
            const Spacer(flex: 3),
            // Actions.
            Padding(
              padding: const EdgeInsets.only(bottom: 48),
              child: _actions(context, ref, l10n, session.phase),
            ),
          ],
        ),
      ),
    );
  }

  Widget _actions(BuildContext context, WidgetRef ref, AppLocalizations l10n,
      CallPhase phase) {
    final notifier = ref.read(callProvider.notifier);

    if (phase == CallPhase.incoming) {
      return Row(
        mainAxisAlignment: MainAxisAlignment.spaceEvenly,
        children: [
          _CallButton(
            icon: FontAwesomeIcons.phoneSlash,
            label: l10n.callDecline,
            color: const Color(0xFFE53935),
            onTap: notifier.decline,
          ),
          _CallButton(
            icon: FontAwesomeIcons.phone,
            label: l10n.callAnswer,
            color: const Color(0xFF43A047),
            onTap: notifier.answer,
          ),
        ],
      );
    }

    // outgoing / active / ended → a single end button.
    return _CallButton(
      icon: FontAwesomeIcons.phoneSlash,
      label: l10n.callEnd,
      color: const Color(0xFFE53935),
      onTap: phase == CallPhase.ended ? notifier.dismiss : notifier.hangUp,
    );
  }

  static String _shortFp(String fp) =>
      fp.length >= 8 ? '${fp.substring(0, 8)}…' : fp;
}

class _CallButton extends StatelessWidget {
  final IconData icon;
  final String label;
  final Color color;
  final VoidCallback onTap;

  const _CallButton({
    required this.icon,
    required this.label,
    required this.color,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        Semantics(
          button: true,
          label: label,
          child: InkWell(
            onTap: onTap,
            customBorder: const CircleBorder(),
            child: Container(
              width: 68,
              height: 68,
              decoration: BoxDecoration(color: color, shape: BoxShape.circle),
              child: Center(
                child: FaIcon(icon, color: Colors.white, size: 26),
              ),
            ),
          ),
        ),
        const SizedBox(height: 10),
        Text(label, style: Theme.of(context).textTheme.labelLarge),
      ],
    );
  }
}
