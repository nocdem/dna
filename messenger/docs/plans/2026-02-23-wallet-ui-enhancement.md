# Wallet Screen UI Enhancement Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Upgrade the wallet screen with a Trust Wallet-style gradient hero card, action buttons, card-based token list, and upgraded detail sheet.

**Architecture:** Single-file enhancement of `wallet_screen.dart`. Leverages the existing design system (DnaGradients, DnaCard, DnaButton, DnaChip). No new files needed — all changes are in `lib/screens/wallet/wallet_screen.dart`. The identity name for the hero card comes from `nameResolverProvider` + `currentFingerprintProvider`.

**Tech Stack:** Flutter, Riverpod, design_system components, flutter_svg, font_awesome_flutter

---

### Task 1: Add Hero Gradient Balance Card

**Files:**
- Modify: `dna_messenger_flutter/lib/screens/wallet/wallet_screen.dart`

**Context:**
- The current wallet screen has a plain `AppBar` and jumps straight into a `ListView` with `_AllBalancesSection`
- We need a gradient card at the top showing the user's identity name and supported chain icons
- The identity name comes from resolving `currentFingerprintProvider` via `nameResolverProvider`
- Chain SVG icons are at: `assets/icons/crypto/eth.svg`, `sol.svg`, `cell.svg`, `trx.svg`
- `DnaGradients.primary` provides the cyan→blue gradient
- `DnaGradients.primaryVertical` provides the vertical variant

**Step 1: Add imports needed for hero card**

At the top of `wallet_screen.dart`, add these imports (some may already exist):

```dart
import '../../design_system/design_system.dart';
import '../../providers/engine_provider.dart' show currentFingerprintProvider;
import '../../providers/name_resolver_provider.dart';
```

**Step 2: Create `_WalletHeroCard` widget**

Add this private widget class to `wallet_screen.dart` (before `_AllBalancesSection`):

```dart
class _WalletHeroCard extends ConsumerWidget {
  const _WalletHeroCard();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final fingerprint = ref.watch(currentFingerprintProvider);
    final nameCache = ref.watch(nameResolverProvider);
    final displayName = (fingerprint != null) ? nameCache[fingerprint] : null;

    return Container(
      margin: const EdgeInsets.fromLTRB(16, 8, 16, 16),
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        gradient: DnaGradients.primaryVertical,
        borderRadius: BorderRadius.circular(DnaSpacing.radiusLg),
        boxShadow: [
          BoxShadow(
            color: DnaColors.gradientStart.withValues(alpha: 0.3),
            blurRadius: 16,
            offset: const Offset(0, 6),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // "My Wallet" label
          Text(
            'My Wallet',
            style: const TextStyle(
              color: Colors.white70,
              fontSize: 13,
              fontWeight: FontWeight.w500,
            ),
          ),
          const SizedBox(height: 4),
          // Identity name
          Text(
            displayName ?? 'Wallet',
            style: const TextStyle(
              color: Colors.white,
              fontSize: 28,
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(height: 16),
          // Chain icons row
          Row(
            children: [
              _ChainIcon('assets/icons/crypto/cell.svg', 'CELL'),
              const SizedBox(width: 12),
              _ChainIcon('assets/icons/crypto/eth.svg', 'ETH'),
              const SizedBox(width: 12),
              _ChainIcon('assets/icons/crypto/sol.svg', 'SOL'),
              const SizedBox(width: 12),
              _ChainIcon('assets/icons/crypto/trx.svg', 'TRX'),
            ],
          ),
        ],
      ),
    );
  }
}

class _ChainIcon extends StatelessWidget {
  final String assetPath;
  final String label;

  const _ChainIcon(this.assetPath, this.label);

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Container(
          width: 32,
          height: 32,
          padding: const EdgeInsets.all(4),
          decoration: BoxDecoration(
            color: Colors.white.withValues(alpha: 0.15),
            borderRadius: BorderRadius.circular(DnaSpacing.radiusFull),
          ),
          child: SvgPicture.asset(
            assetPath,
            fit: BoxFit.contain,
          ),
        ),
        const SizedBox(height: 4),
        Text(
          label,
          style: const TextStyle(
            color: Colors.white70,
            fontSize: 10,
            fontWeight: FontWeight.w500,
          ),
        ),
      ],
    );
  }
}
```

**Step 3: Wire hero card into the main layout**

In `_buildContent`, replace the current `ListView` body with:

```dart
return RefreshIndicator(
  onRefresh: () async {
    await ref.read(walletsProvider.notifier).refresh();
    ref.invalidate(allBalancesProvider);
  },
  child: ListView(
    children: [
      const _WalletHeroCard(),
      const _ActionButtonsRow(),  // Added in Task 2
      const _AllBalancesSection(),
    ],
  ),
);
```

Note: `_ActionButtonsRow()` will be created in Task 2 — for now you can comment it out or create a stub.

**Step 4: Remove old AppBar actions (address book + refresh moved)**

Change the AppBar in the `build()` method to use `DnaAppBar` style (no actions — refresh is via pull-to-refresh, address book moves to action buttons or More screen):

```dart
appBar: AppBar(
  title: const Text('Wallet'),
),
```

(Keep it simple — the hero card and pull-to-refresh replace the old action buttons.)

**Step 5: Build and verify**

```bash
cd /opt/dna-messenger/dna_messenger_flutter && flutter build linux 2>&1
```

Expected: Build succeeds with no errors.

**Step 6: Commit**

```bash
cd /opt/dna-messenger && git add dna_messenger_flutter/lib/screens/wallet/wallet_screen.dart
git commit -m "feat(wallet): add gradient hero card with identity name and chain icons"
```

---

### Task 2: Add Action Buttons Row (Send + Receive)

**Files:**
- Modify: `dna_messenger_flutter/lib/screens/wallet/wallet_screen.dart`

**Context:**
- Two circular buttons below the hero card: Send and Receive
- Send opens `_SendSheet` (already exists)
- Receive opens a bottom sheet showing wallet address + QR placeholder
- Buttons have gradient borders using `DnaGradients.primary`
- The `_ActionButtons` class already exists (line ~553) but is marked `// ignore: unused_element` — we'll create a new cleaner version

**Step 1: Create `_ActionButtonsRow` widget**

```dart
class _ActionButtonsRow extends ConsumerWidget {
  const _ActionButtonsRow();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final wallets = ref.watch(walletsProvider);

    return Padding(
      padding: const EdgeInsets.only(bottom: 24),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          _CircularAction(
            icon: FontAwesomeIcons.arrowUp,
            label: 'Send',
            onTap: () {
              wallets.whenData((list) {
                if (list.isNotEmpty) {
                  showModalBottomSheet(
                    context: context,
                    isScrollControlled: true,
                    builder: (context) => _SendSheet(walletIndex: 0),
                  );
                }
              });
            },
          ),
          const SizedBox(width: 40),
          _CircularAction(
            icon: FontAwesomeIcons.arrowDown,
            label: 'Receive',
            onTap: () {
              wallets.whenData((list) {
                if (list.isNotEmpty) {
                  _showReceiveSheet(context, list.first);
                }
              });
            },
          ),
        ],
      ),
    );
  }

  void _showReceiveSheet(BuildContext context, Wallet wallet) {
    showModalBottomSheet(
      context: context,
      builder: (context) => SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                'Receive',
                style: Theme.of(context).textTheme.titleLarge,
              ),
              const SizedBox(height: 16),
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: Colors.white,
                  borderRadius: BorderRadius.circular(12),
                ),
                child: const FaIcon(
                  FontAwesomeIcons.qrcode,
                  size: 150,
                  color: Colors.black,
                ),
              ),
              const SizedBox(height: 16),
              Text(
                wallet.address,
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                  fontFamily: 'monospace',
                ),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 16),
              DnaButton(
                label: 'Copy Address',
                icon: FontAwesomeIcons.copy,
                expand: true,
                onPressed: () {
                  Clipboard.setData(ClipboardData(text: wallet.address));
                  final messenger = ScaffoldMessenger.of(context);
                  Navigator.pop(context);
                  messenger.showSnackBar(
                    const SnackBar(content: Text('Address copied')),
                  );
                },
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _CircularAction extends StatelessWidget {
  final IconData icon;
  final String label;
  final VoidCallback onTap;

  const _CircularAction({
    required this.icon,
    required this.label,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 56,
            height: 56,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              gradient: DnaGradients.primary,
              boxShadow: [
                BoxShadow(
                  color: DnaColors.gradientStart.withValues(alpha: 0.3),
                  blurRadius: 8,
                  offset: const Offset(0, 3),
                ),
              ],
            ),
            child: Icon(
              icon,
              color: Colors.white,
              size: 22,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            label,
            style: Theme.of(context).textTheme.labelMedium,
          ),
        ],
      ),
    );
  }
}
```

**Step 2: Uncomment `_ActionButtonsRow()` in the ListView (from Task 1 Step 3)**

Make sure the ListView now includes:
```dart
const _WalletHeroCard(),
const _ActionButtonsRow(),
const _AllBalancesSection(),
```

**Step 3: Delete old `_ActionButtons` class** (the unused one around line ~553) and the old `_WalletCard` widget (~line 280) since they're both `// ignore: unused_element`.

**Step 4: Build and verify**

```bash
cd /opt/dna-messenger/dna_messenger_flutter && flutter build linux 2>&1
```

**Step 5: Commit**

```bash
cd /opt/dna-messenger && git add dna_messenger_flutter/lib/screens/wallet/wallet_screen.dart
git commit -m "feat(wallet): add Send/Receive circular action buttons with gradient"
```

---

### Task 3: Upgrade Token List to Cards

**Files:**
- Modify: `dna_messenger_flutter/lib/screens/wallet/wallet_screen.dart`

**Context:**
- Currently `_AllBalancesSection` renders `_BalanceTile` using plain `ListTile`
- Upgrade to use `DnaCard` with proper layout: SVG icon, token name + network chip, balance + chevron
- Add "Assets" section header with token count

**Step 1: Add section header to `_AllBalancesSection`**

Add a header row at the top of the `Column` in `_AllBalancesSection.build()`:

```dart
Padding(
  padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
  child: Row(
    children: [
      Text(
        'Assets',
        style: theme.textTheme.titleMedium?.copyWith(
          fontWeight: FontWeight.bold,
        ),
      ),
      const SizedBox(width: 8),
      // Token count badge
      if (filteredList is List)
        DnaChip(label: '${filteredList.length}'),
    ],
  ),
),
```

Note: The count badge logic will need to be adjusted since `filteredList` is computed inside the `when` callback. Restructure so the header is part of the data branch.

**Step 2: Replace `_BalanceTile` with a card-based layout**

Rewrite `_BalanceTile.build()` to use `DnaCard`:

```dart
@override
Widget build(BuildContext context, WidgetRef ref) {
  final theme = Theme.of(context);
  final balance = walletBalance.balance;
  final iconPath = getTokenIconPath(balance.token);

  return DnaCard(
    margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
    padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
    onTap: () => _showTokenDetails(context, ref),
    child: Row(
      children: [
        // Token icon
        iconPath != null
            ? SizedBox(
                width: 40,
                height: 40,
                child: SvgPicture.asset(iconPath, fit: BoxFit.contain),
              )
            : CircleAvatar(
                backgroundColor: _getTokenColor(balance.token).withValues(alpha: 0.2),
                radius: 20,
                child: Text(
                  balance.token.isNotEmpty ? balance.token[0].toUpperCase() : '?',
                  style: TextStyle(
                    color: _getTokenColor(balance.token),
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
        const SizedBox(width: 12),
        // Token name + network chip
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                balance.token,
                style: theme.textTheme.titleSmall?.copyWith(
                  fontWeight: FontWeight.w600,
                ),
              ),
              const SizedBox(height: 4),
              DnaChip(label: getNetworkDisplayLabel(balance.network)),
            ],
          ),
        ),
        // Balance + chevron
        Column(
          crossAxisAlignment: CrossAxisAlignment.end,
          children: [
            Text(
              balance.balance,
              style: theme.textTheme.titleSmall?.copyWith(
                fontWeight: FontWeight.bold,
              ),
            ),
          ],
        ),
        const SizedBox(width: 8),
        FaIcon(
          FontAwesomeIcons.chevronRight,
          size: 14,
          color: theme.colorScheme.onSurface.withValues(alpha: 0.3),
        ),
      ],
    ),
  );
}
```

**Step 3: Build and verify**

```bash
cd /opt/dna-messenger/dna_messenger_flutter && flutter build linux 2>&1
```

**Step 4: Commit**

```bash
cd /opt/dna-messenger && git add dna_messenger_flutter/lib/screens/wallet/wallet_screen.dart
git commit -m "feat(wallet): upgrade token list with DnaCard layout and network chips"
```

---

### Task 4: Upgrade Token Detail Sheet

**Files:**
- Modify: `dna_messenger_flutter/lib/screens/wallet/wallet_screen.dart`

**Context:**
- `_TokenDetailSheet` is the bottom sheet opened when tapping a token
- Upgrade with: gradient header, DnaButton for Send, better transaction cards
- Current implementation starts at ~line 1486

**Step 1: Add gradient header to `_TokenDetailSheet`**

Replace the current header section (the `Padding(padding: const EdgeInsets.all(16)...` block) with a gradient container:

```dart
// Gradient header
Container(
  width: double.infinity,
  padding: const EdgeInsets.all(20),
  decoration: BoxDecoration(
    gradient: DnaGradients.primaryVertical,
  ),
  child: SafeArea(
    bottom: false,
    child: Column(
      children: [
        // Token icon + balance
        Row(
          children: [
            // Token icon (48px)
            iconPath != null
                ? SizedBox(
                    width: 48,
                    height: 48,
                    child: SvgPicture.asset(iconPath, fit: BoxFit.contain),
                  )
                : CircleAvatar(
                    backgroundColor: Colors.white.withValues(alpha: 0.2),
                    radius: 24,
                    child: Text(
                      token.isNotEmpty ? token[0].toUpperCase() : '?',
                      style: const TextStyle(
                        color: Colors.white,
                        fontWeight: FontWeight.bold,
                        fontSize: 20,
                      ),
                    ),
                  ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    '$balance $token',
                    style: const TextStyle(
                      color: Colors.white,
                      fontSize: 24,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  Text(
                    getNetworkDisplayLabel(network),
                    style: const TextStyle(
                      color: Colors.white70,
                      fontSize: 13,
                    ),
                  ),
                ],
              ),
            ),
            IconButton(
              icon: const FaIcon(FontAwesomeIcons.arrowsRotate, color: Colors.white70),
              onPressed: () {
                ref.invalidate(balancesProvider(walletIndex));
                ref.invalidate(transactionsProvider((walletIndex: walletIndex, network: network == 'Ethereum' ? 'Ethereum' : 'Backbone')));
              },
              tooltip: 'Refresh',
            ),
          ],
        ),
        const SizedBox(height: 16),
        // Send button (gradient style from DnaButton)
        SizedBox(
          width: double.infinity,
          child: ElevatedButton.icon(
            onPressed: () => _showSend(context, ref, balance),
            icon: const FaIcon(FontAwesomeIcons.arrowUp, size: 16, color: Colors.white),
            label: Text('Send $token', style: const TextStyle(color: Colors.white)),
            style: ElevatedButton.styleFrom(
              backgroundColor: Colors.white.withValues(alpha: 0.2),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(DnaSpacing.radiusMd),
              ),
              padding: const EdgeInsets.symmetric(vertical: 12),
            ),
          ),
        ),
      ],
    ),
  ),
),
```

**Step 2: Upgrade address section**

Move the address section below the gradient header with proper styling:

```dart
// Address section
Padding(
  padding: const EdgeInsets.all(16),
  child: DnaCard(
    padding: const EdgeInsets.all(12),
    child: Row(
      children: [
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Address',
                style: theme.textTheme.labelSmall?.copyWith(
                  color: theme.colorScheme.primary,
                ),
              ),
              const SizedBox(height: 4),
              Text(
                walletAddress,
                style: theme.textTheme.bodySmall?.copyWith(fontFamily: 'monospace'),
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
              ),
            ],
          ),
        ),
        IconButton(
          icon: const FaIcon(FontAwesomeIcons.copy, size: 18),
          onPressed: () {
            Clipboard.setData(ClipboardData(text: walletAddress));
            ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(content: Text('Address copied'), duration: Duration(seconds: 2)),
            );
          },
          tooltip: 'Copy address',
        ),
      ],
    ),
  ),
),
```

**Step 3: Upgrade `_TransactionTile` with DnaCard wrapping**

Wrap each transaction in a subtle card instead of plain ListTile:

```dart
@override
Widget build(BuildContext context) {
  final theme = Theme.of(context);
  final isReceived = transaction.direction.toLowerCase() == 'received';

  return DnaCard(
    margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 3),
    padding: const EdgeInsets.all(12),
    onTap: () => _showDetails(context),
    child: Row(
      children: [
        // Direction icon
        CircleAvatar(
          radius: 18,
          backgroundColor: isReceived
              ? DnaColors.textSuccess.withValues(alpha: 0.15)
              : DnaColors.textError.withValues(alpha: 0.15),
          child: FaIcon(
            isReceived ? FontAwesomeIcons.arrowDown : FontAwesomeIcons.arrowUp,
            size: 14,
            color: isReceived ? DnaColors.textSuccess : DnaColors.textError,
          ),
        ),
        const SizedBox(width: 12),
        // Amount + address + time
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                '${transaction.amount} ${transaction.token}',
                style: theme.textTheme.titleSmall?.copyWith(fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 2),
              Text(
                _formatAddress(transaction.otherAddress),
                style: theme.textTheme.bodySmall?.copyWith(fontFamily: 'monospace'),
              ),
              Text(
                _formatTimestamp(transaction.timestamp),
                style: theme.textTheme.labelSmall,
              ),
            ],
          ),
        ),
        // Status chip
        _StatusChip(status: transaction.status),
      ],
    ),
  );
}
```

**Step 4: Remove the handle bar from `_TokenDetailSheet` (the gradient header replaces it)**

The existing handle bar code:
```dart
Container(
  margin: const EdgeInsets.only(top: 8),
  width: 40,
  height: 4,
  ...
),
```
Keep it if desired for the drag affordance, or remove since the gradient header provides visual distinction.

**Step 5: Build and verify**

```bash
cd /opt/dna-messenger/dna_messenger_flutter && flutter build linux 2>&1
```

**Step 6: Commit**

```bash
cd /opt/dna-messenger && git add dna_messenger_flutter/lib/screens/wallet/wallet_screen.dart
git commit -m "feat(wallet): upgrade token detail sheet with gradient header and card-based transactions"
```

---

### Task 5: Clean Up and Delete Unused Code

**Files:**
- Modify: `dna_messenger_flutter/lib/screens/wallet/wallet_screen.dart`

**Context:**
- After Tasks 1-4, several old widgets are unused: `_WalletSelector`, `_WalletCard`, old `_ActionButtons`, `_TransactionHistorySheet`
- All are marked `// ignore: unused_element`
- Delete them to reduce file size

**Step 1: Delete these unused widgets:**
- `_WalletSelector` (~line 173-277)
- `_WalletCard` (~line 280-390)
- Old `_ActionButtons` (~line 553-648) — replaced by `_ActionButtonsRow` + `_CircularAction`
- `_TransactionHistorySheet` (~line 1758-1898) — replaced by `_TokenDetailSheet` which now shows history inline

**Step 2: Build and verify**

```bash
cd /opt/dna-messenger/dna_messenger_flutter && flutter build linux 2>&1
```

**Step 3: Commit**

```bash
cd /opt/dna-messenger && git add dna_messenger_flutter/lib/screens/wallet/wallet_screen.dart
git commit -m "refactor(wallet): remove unused legacy widgets"
```

---

### Task 6: Version Bump + Documentation

**Files:**
- Modify: `dna_messenger_flutter/pubspec.yaml` — bump version
- Modify: `CLAUDE.md` — update Flutter version in header
- Modify: `docs/FLUTTER_UI.md` — update wallet screen description if needed

**Step 1: Bump pubspec.yaml version**

Change from `0.100.95+10195` to `0.100.96+10196`

**Step 2: Update CLAUDE.md header**

Update the Versions line to show `Flutter v0.100.96`

**Step 3: Update CLAUDE.md version table**

Update the Flutter App row: `v0.100.96+10196`

**Step 4: Commit**

```bash
cd /opt/dna-messenger && git add dna_messenger_flutter/pubspec.yaml CLAUDE.md
git commit -m "feat(wallet): wallet UI enhancement with Trust Wallet-style visuals (v0.100.96)"
```
