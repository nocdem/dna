// Stake Onboarding Sheet — shown once on first visit to the stake dashboard.
//
// Three-page PageView walking the user through the witness concept using
// the non-technical framing agreed with punk 2026-04-24:
//   1. Witnesses run the network (like an on-duty crew)
//   2. Back one and share the reward
//   3. You can pull your DNAC back anytime — no give-away
//
// Dismiss is terminal: the "Anladım" button sets a shared_preferences flag
// so the sheet never shows again. There is no "Skip" button by design —
// the sheet is short enough to read end-to-end and the concept matters for
// informed consent before the user locks any DNAC.

import 'package:flutter/material.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../l10n/app_localizations.dart';

/// Shared-preferences key — bump the suffix if the onboarding content
/// changes enough that returning users should see it again.
const String kStakeOnboardingShownKey = 'onboarding_stake_shown_v1';

class StakeOnboardingSheet extends StatefulWidget {
  const StakeOnboardingSheet({super.key});

  /// Show the sheet and persist the "shown" flag on dismiss. Idempotent —
  /// safe to call every time the stake screen opens; the caller still has
  /// to check the flag first to avoid even opening it.
  static Future<void> show(BuildContext context) async {
    await showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      isDismissible: false,
      enableDrag: false,
      backgroundColor: Theme.of(context).colorScheme.surface,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (_) => const StakeOnboardingSheet(),
    );
  }

  @override
  State<StakeOnboardingSheet> createState() => _StakeOnboardingSheetState();
}

class _StakeOnboardingSheetState extends State<StakeOnboardingSheet> {
  final PageController _controller = PageController();
  int _page = 0;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  Future<void> _dismiss() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool(kStakeOnboardingShownKey, true);
    if (mounted) Navigator.of(context).pop();
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    final theme = Theme.of(context);
    final pages = <_OnboardingPage>[
      _OnboardingPage(
        icon: FontAwesomeIcons.shieldHalved,
        title: l10n.onboardingStakeP1Title,
        body: l10n.onboardingStakeP1Body,
      ),
      _OnboardingPage(
        icon: FontAwesomeIcons.handHoldingDollar,
        title: l10n.onboardingStakeP2Title,
        body: l10n.onboardingStakeP2Body,
      ),
      _OnboardingPage(
        icon: FontAwesomeIcons.arrowRotateLeft,
        title: l10n.onboardingStakeP3Title,
        body: l10n.onboardingStakeP3Body,
      ),
    ];

    return SafeArea(
      child: SizedBox(
        height: MediaQuery.of(context).size.height * 0.6,
        child: Column(
          children: [
            const SizedBox(height: 16),
            // Progress dots — visual affordance for "3 pages"
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: List.generate(pages.length, (i) {
                final active = i == _page;
                return AnimatedContainer(
                  duration: const Duration(milliseconds: 200),
                  margin: const EdgeInsets.symmetric(horizontal: 4),
                  width: active ? 24 : 8,
                  height: 8,
                  decoration: BoxDecoration(
                    color: active
                        ? theme.colorScheme.primary
                        : theme.colorScheme.primary.withAlpha(60),
                    borderRadius: BorderRadius.circular(4),
                  ),
                );
              }),
            ),
            const SizedBox(height: 24),
            Expanded(
              child: PageView(
                controller: _controller,
                onPageChanged: (i) => setState(() => _page = i),
                children: pages,
              ),
            ),
            Padding(
              padding: const EdgeInsets.all(20),
              child: SizedBox(
                width: double.infinity,
                child: ElevatedButton(
                  onPressed: () {
                    if (_page < pages.length - 1) {
                      _controller.nextPage(
                        duration: const Duration(milliseconds: 240),
                        curve: Curves.easeInOut,
                      );
                    } else {
                      _dismiss();
                    }
                  },
                  style: ElevatedButton.styleFrom(
                    padding: const EdgeInsets.symmetric(vertical: 14),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(12),
                    ),
                  ),
                  child: Text(
                    _page < pages.length - 1
                        ? l10n.onboardingStakeNext
                        : l10n.onboardingStakeGotIt,
                    style: const TextStyle(
                      fontSize: 16,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _OnboardingPage extends StatelessWidget {
  const _OnboardingPage({
    required this.icon,
    required this.title,
    required this.body,
  });

  final IconData icon;
  final String title;
  final String body;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 28),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          FaIcon(icon, size: 56, color: theme.colorScheme.primary),
          const SizedBox(height: 28),
          Text(
            title,
            textAlign: TextAlign.center,
            style: theme.textTheme.titleLarge?.copyWith(
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(height: 14),
          Text(
            body,
            textAlign: TextAlign.center,
            style: theme.textTheme.bodyMedium?.copyWith(
              color: theme.colorScheme.onSurface.withAlpha(180),
              height: 1.4,
            ),
          ),
        ],
      ),
    );
  }
}
