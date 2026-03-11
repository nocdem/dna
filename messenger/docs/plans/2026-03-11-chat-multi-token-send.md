# Chat Multi-Token Send — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Extend the chat "Send CPUNK" button to support sending any token (CELL, CPUNK, USDC, USDT, ETH, SOL, TRX) on any supported chain, and rename all "Backbone" references to "Cellframe".

**Architecture:** The C engine already supports multi-chain token sends via `dna_engine_send_tokens()`. Flutter's `sendTokens()` provider also works for any chain/token. The work is: (1) rename "Backbone" → "Cellframe" in C engine balance responses, (2) rewrite `_ChatSendSheet` to support token/chain selection with dynamic balance lookup and address resolution, (3) rename "Backbone" → "Cellframe" throughout Flutter codebase.

**Tech Stack:** C (engine), Dart/Flutter (UI), Riverpod (state)

---

### Task 1: Rename "Backbone" → "Cellframe" in C Engine Balance Responses

The C engine hardcodes `"Backbone"` as the network name for Cellframe balances. Flutter reads this to match tokens. Change it to `"Cellframe"`.

**Files:**
- Modify: `messenger/src/api/engine/dna_engine_wallet.c:281-304`

**Step 1: Update balance network strings**

In `dna_engine_wallet.c`, find the balance initialization block (around line 278-304) and change all `"Backbone"` to `"Cellframe"`:

```c
    // Change these 5 lines:
    strncpy(balances[0].network, "Cellframe", sizeof(balances[0].network) - 1);
    // ... (lines 285, 289, 293, 297 — same change)
```

Also update the RPC call on line 304:
```c
    int rc = cellframe_rpc_get_balance("Backbone", address, "CPUNK", &response);
```
**NOTE:** Do NOT change this RPC parameter — `"Backbone"` is the actual Cellframe network name used by the RPC API. Only change the `balances[].network` display strings.

Also update the default comment on line 423:
```c
        /* Default: Cellframe */
```

**Step 2: Build C library**

Run: `cd /opt/dna/messenger/build && cmake .. && make -j$(nproc)`
Expected: Clean build, zero warnings, zero errors.

**Step 3: Commit**

```bash
git add messenger/src/api/engine/dna_engine_wallet.c
git commit -m "refactor: rename Backbone → Cellframe in balance network strings"
```

---

### Task 2: Rename "Backbone" → "Cellframe" in Flutter Codebase

All Flutter code that references "Backbone" as a network name needs updating. The `UserProfile.backbone` field name stays (it's a struct field matching C FFI), but string literals change.

**Files:**
- Modify: `messenger/dna_messenger_flutter/lib/screens/chat/chat_screen.dart`
- Modify: `messenger/dna_messenger_flutter/lib/screens/wallet/wallet_screen.dart`
- Modify: `messenger/dna_messenger_flutter/lib/screens/wallet/address_dialog.dart`
- Modify: `messenger/dna_messenger_flutter/lib/screens/wallet/address_book_screen.dart`
- Modify: `messenger/dna_messenger_flutter/lib/providers/wallet_provider.dart`
- Modify: `messenger/dna_messenger_flutter/lib/ffi/dna_engine.dart`

**Step 1: Update wallet_provider.dart**

In `_getProfileAddress()` (line 360-372), change the case label:
```dart
      case 'cellframe':  // was 'backbone'
        return profile.backbone;
```

**Step 2: Update dna_engine.dart**

In `networkDisplayName()` (line 141), change:
```dart
      case 'backbone':
```
to:
```dart
      case 'cellframe':
```

**Step 3: Update wallet_screen.dart**

All `'Backbone'` and `'backbone'` string references:
- Line 67: `default:` comment — update to mention Cellframe
- Line 81: `case 'backbone':` → `case 'cellframe':`
- Line 384: `String _selectedNetwork = 'backbone';` → `'cellframe'`
- Line 387: `('backbone', 'CF20', ...)` → `('cellframe', 'CF20', ...)`
- Line 629, 632: `'backbone'` → `'cellframe'`
- Line 771: `'backbone'` → `'cellframe'`
- Line 1047-1051: Rename `_backboneNetworkFee` → `_cellframeNetworkFee`, etc.
- Line 1112: Comment update
- Line 1156: `'Backbone'` → `'Cellframe'`
- Line 1212-1213: Comment update
- Line 1227: `return 'Backbone'` → `return 'Cellframe'`
- Line 1569: `'Backbone'` → `'Cellframe'`
- Line 1627-1628: `'Backbone'` → `'Cellframe'`
- Line 1639, 1646, 1653: Update fee variable names
- Line 1708: Comment update
- Line 1728: `value: 'Backbone'` → `value: 'Cellframe'`
- Line 1777: `'backbone'` → `'cellframe'`

**Step 4: Update address_dialog.dart**

- Line 53: `('backbone', 'Cellframe (CF20)')` → `('cellframe', 'Cellframe (CF20)')`
- Line 67: `'backbone'` → `'cellframe'`
- Line 196, 211: `case 'backbone':` → `case 'cellframe':`

**Step 5: Update address_book_screen.dart**

- Line 238: `case 'backbone':` → `case 'cellframe':`

**Step 6: Update chat_screen.dart (Backbone references only, not the multi-token yet)**

- Line 2241-2245: Rename `_backboneNetworkFee` → `_cellframeNetworkFee`, etc.
- Line 2269: `'Contact has no Backbone wallet'` → `'Contact has no Cellframe wallet'`
- Line 2298: `b.network == 'Backbone'` → `b.network == 'Cellframe'`
- Line 2361: `network: 'Backbone'` → `network: 'Cellframe'`
- Line 2371: `'network': 'Backbone'` → `'network': 'Cellframe'`
- Line 2551-2555: Update fee variable names
- Line 2951: `?? 'Backbone'` → `?? 'Cellframe'`

**Step 7: Build Flutter**

Run: `cd /opt/dna/messenger/dna_messenger_flutter && flutter build linux`
Expected: Clean build.

**Step 8: Commit**

```bash
git add -A messenger/dna_messenger_flutter/lib/
git commit -m "refactor: rename Backbone → Cellframe throughout Flutter codebase"
```

---

### Task 3: Rewrite `_ChatSendSheet` for Multi-Token Support

Replace the CPUNK-only `_ChatSendSheet` with a multi-token version that supports all chains and tokens.

**Files:**
- Modify: `messenger/dna_messenger_flutter/lib/screens/chat/chat_screen.dart`

**Step 1: Update the button tooltip**

Change lines 405-410 from:
```dart
                // Send CPUNK button
                IconButton(
                  icon: const FaIcon(FontAwesomeIcons.dollarSign),
                  tooltip: 'Send CPUNK',
                  onPressed: () => _showSendCpunk(context, contact),
                ),
```
to:
```dart
                // Send tokens button
                IconButton(
                  icon: const FaIcon(FontAwesomeIcons.dollarSign),
                  tooltip: 'Send Tokens',
                  onPressed: () => _showSendTokens(context, contact),
                ),
```

**Step 2: Rename `_showSendCpunk` → `_showSendTokens`**

At line 1159, rename the method:
```dart
  void _showSendTokens(BuildContext context, Contact contact) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (context) => _ChatSendSheet(contact: contact),
    );
  }
```

**Step 3: Define the token/chain data model**

Add above `_ChatSendSheet` class (around line 2222):

```dart
/// Token entry for the send sheet dropdown
class _TokenOption {
  final String token;      // Token ticker: CELL, CPUNK, USDC, USDT, ETH, SOL, TRX
  final String network;    // Network for API: Cellframe, Ethereum, Solana, Tron
  final String chain;      // Chain for JSON: cellframe, ethereum, solana, tron
  final String displayName; // UI label: "CELL (Cellframe)", "USDT (Ethereum)"
  final String profileField; // Which UserProfile field has the address: backbone, eth, sol, trx

  const _TokenOption({
    required this.token,
    required this.network,
    required this.chain,
    required this.displayName,
    required this.profileField,
  });

  /// All possible token options
  static const List<_TokenOption> all = [
    // Cellframe (requires backbone address)
    _TokenOption(token: 'CELL', network: 'Cellframe', chain: 'cellframe', displayName: 'CELL (Cellframe)', profileField: 'backbone'),
    _TokenOption(token: 'CPUNK', network: 'Cellframe', chain: 'cellframe', displayName: 'CPUNK (Cellframe)', profileField: 'backbone'),
    _TokenOption(token: 'USDC', network: 'Cellframe', chain: 'cellframe', displayName: 'USDC (Cellframe)', profileField: 'backbone'),
    // Ethereum (requires eth address)
    _TokenOption(token: 'ETH', network: 'Ethereum', chain: 'ethereum', displayName: 'ETH (Ethereum)', profileField: 'eth'),
    _TokenOption(token: 'USDT', network: 'Ethereum', chain: 'ethereum', displayName: 'USDT (Ethereum)', profileField: 'eth'),
    _TokenOption(token: 'USDC', network: 'Ethereum', chain: 'ethereum', displayName: 'USDC (Ethereum)', profileField: 'eth'),
    // Solana (requires sol address)
    _TokenOption(token: 'SOL', network: 'Solana', chain: 'solana', displayName: 'SOL (Solana)', profileField: 'sol'),
    _TokenOption(token: 'USDT', network: 'Solana', chain: 'solana', displayName: 'USDT (Solana)', profileField: 'sol'),
    _TokenOption(token: 'USDC', network: 'Solana', chain: 'solana', displayName: 'USDC (Solana)', profileField: 'sol'),
    // TRON (requires trx address)
    _TokenOption(token: 'TRX', network: 'Tron', chain: 'tron', displayName: 'TRX (TRON)', profileField: 'trx'),
    _TokenOption(token: 'USDT', network: 'Tron', chain: 'tron', displayName: 'USDT (TRON)', profileField: 'trx'),
    _TokenOption(token: 'USDC', network: 'Tron', chain: 'tron', displayName: 'USDC (TRON)', profileField: 'trx'),
  ];

  /// Filter options by which addresses the contact has
  static List<_TokenOption> forProfile(UserProfile profile) {
    return all.where((opt) {
      switch (opt.profileField) {
        case 'backbone': return profile.backbone.isNotEmpty;
        case 'eth': return profile.eth.isNotEmpty;
        case 'sol': return profile.sol.isNotEmpty;
        case 'trx': return profile.trx.isNotEmpty;
        default: return false;
      }
    }).toList();
  }

  /// Get the recipient address from a profile
  String getAddress(UserProfile profile) {
    switch (profileField) {
      case 'backbone': return profile.backbone;
      case 'eth': return profile.eth;
      case 'sol': return profile.sol;
      case 'trx': return profile.trx;
      default: return '';
    }
  }
}
```

**Step 4: Rewrite `_ChatSendSheetState`**

Replace the entire `_ChatSendSheetState` class with multi-token support:

```dart
class _ChatSendSheetState extends ConsumerState<_ChatSendSheet> {
  final _amountController = TextEditingController();
  bool _isSending = false;
  String? _sendError;
  bool _isResolving = true;
  int _selectedGasSpeed = 1; // 0=slow, 1=normal, 2=fast

  // Resolved profile and available tokens
  UserProfile? _contactProfile;
  List<_TokenOption> _availableTokens = [];
  _TokenOption? _selectedToken;

  // Cellframe network fees
  static const double _cellframeNetworkFee = 0.002;
  static const double _cellframeValidatorSlow = 0.0001;
  static const double _cellframeValidatorNormal = 0.01;
  static const double _cellframeValidatorFast = 0.05;

  @override
  void initState() {
    super.initState();
    _resolveContactProfile();
  }

  @override
  void dispose() {
    _amountController.dispose();
    super.dispose();
  }

  Future<void> _resolveContactProfile() async {
    try {
      final engine = await ref.read(engineProvider.future);
      final profile = await engine.lookupProfile(widget.contact.fingerprint);

      if (!mounted) return;

      if (profile == null) {
        setState(() {
          _isResolving = false;
        });
        return;
      }

      final tokens = _TokenOption.forProfile(profile);
      setState(() {
        _isResolving = false;
        _contactProfile = profile;
        _availableTokens = tokens;
        _selectedToken = tokens.isNotEmpty ? tokens.first : null;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _isResolving = false;
      });
    }
  }

  /// Get balance for the currently selected token
  String? _getSelectedBalance() {
    if (_selectedToken == null) return null;
    final walletsAsync = ref.watch(walletsProvider);
    return walletsAsync.whenOrNull(
      data: (wallets) {
        if (wallets.isEmpty) return null;
        final balancesAsync = ref.watch(balancesProvider(0));
        return balancesAsync.whenOrNull(
          data: (balances) {
            for (final b in balances) {
              if (b.token == _selectedToken!.token &&
                  b.network.toLowerCase() == _selectedToken!.network.toLowerCase()) {
                return b.balance;
              }
            }
            return null;
          },
        );
      },
    );
  }

  double? _calculateMaxAmount() {
    final balanceStr = _getSelectedBalance();
    if (balanceStr == null || balanceStr.isEmpty) return null;
    final balance = double.tryParse(balanceStr);
    if (balance == null || balance <= 0) return null;
    return balance;
  }

  bool _canSend() {
    if (_isSending || _isResolving) return false;
    if (_selectedToken == null || _contactProfile == null) return false;
    if (_amountController.text.trim().isEmpty) return false;
    final amount = double.tryParse(_amountController.text.trim());
    if (amount == null || amount <= 0) return false;
    return true;
  }

  Future<void> _send() async {
    setState(() {
      _sendError = null;
      _isSending = true;
    });

    final amountStr = _amountController.text.trim();
    final amount = double.tryParse(amountStr);
    final maxAmount = _calculateMaxAmount();

    if (amount == null || amount <= 0) {
      setState(() {
        _isSending = false;
        _sendError = 'Please enter a valid amount';
      });
      return;
    }

    if (maxAmount != null && amount > maxAmount) {
      setState(() {
        _isSending = false;
        _sendError = 'Insufficient ${_selectedToken!.token} balance';
      });
      return;
    }

    final recipientAddress = _selectedToken!.getAddress(_contactProfile!);
    if (recipientAddress.isEmpty) {
      setState(() {
        _isSending = false;
        _sendError = 'Contact has no wallet for this network';
      });
      return;
    }

    try {
      final txHash = await ref.read(walletsProvider.notifier).sendTokens(
        walletIndex: 0,
        recipientAddress: recipientAddress,
        amount: amountStr,
        token: _selectedToken!.token,
        network: _selectedToken!.network,
        gasSpeed: _selectedGasSpeed,
      );

      if (mounted) {
        final transferData = jsonEncode({
          'type': 'token_transfer',
          'amount': amountStr,
          'token': _selectedToken!.token,
          'network': _selectedToken!.network,
          'chain': _selectedToken!.chain,
          'txHash': txHash,
          'recipientAddress': recipientAddress,
          'recipientName': widget.contact.displayName,
        });

        ref.read(conversationProvider(widget.contact.fingerprint).notifier)
            .sendMessage(transferData);

        Navigator.pop(context);
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Sent $amountStr ${_selectedToken!.token}'),
            backgroundColor: DnaColors.snackbarSuccess,
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        final message = e is DnaEngineException ? e.message : e.toString();
        setState(() {
          _isSending = false;
          _sendError = message;
        });
      }
    }
  }

  bool get _showSpeedSelector => _selectedToken?.chain == 'cellframe';

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final balance = _getSelectedBalance();
    final maxAmount = _calculateMaxAmount();

    return Container(
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        borderRadius: const BorderRadius.vertical(top: Radius.circular(16)),
      ),
      child: Padding(
        padding: EdgeInsets.only(
          left: 24,
          right: 24,
          top: 24,
          bottom: MediaQuery.of(context).viewInsets.bottom + 24,
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // Header
            Row(
              children: [
                const FaIcon(FontAwesomeIcons.moneyBillTransfer, size: 24),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Send Tokens',
                        style: theme.textTheme.titleLarge,
                      ),
                      Text(
                        'to ${widget.contact.displayName.isNotEmpty ? widget.contact.displayName : "contact"}',
                        style: theme.textTheme.bodySmall,
                      ),
                    ],
                  ),
                ),
                IconButton(
                  icon: const FaIcon(FontAwesomeIcons.xmark),
                  onPressed: () => Navigator.pop(context),
                ),
              ],
            ),
            const SizedBox(height: 24),

            // Loading state
            if (_isResolving)
              const Center(
                child: Padding(
                  padding: EdgeInsets.all(16),
                  child: Column(
                    children: [
                      CircularProgressIndicator(),
                      SizedBox(height: 12),
                      Text('Looking up wallet addresses...'),
                    ],
                  ),
                ),
              )
            // No tokens available
            else if (_availableTokens.isEmpty)
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: DnaColors.warning.withAlpha(30),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Row(
                  children: [
                    FaIcon(FontAwesomeIcons.circleExclamation, color: DnaColors.warning),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Text(
                        'Contact has no wallet addresses in their profile',
                        style: TextStyle(color: DnaColors.warning),
                      ),
                    ),
                  ],
                ),
              )
            else ...[
              // Token selector dropdown
              DropdownButtonFormField<_TokenOption>(
                value: _selectedToken,
                decoration: const InputDecoration(
                  labelText: 'Token',
                ),
                items: _availableTokens.map((opt) {
                  return DropdownMenuItem(
                    value: opt,
                    child: Text(opt.displayName),
                  );
                }).toList(),
                onChanged: (opt) {
                  setState(() {
                    _selectedToken = opt;
                    _amountController.clear();
                    _sendError = null;
                  });
                },
              ),
              const SizedBox(height: 16),

              // Resolved address indicator
              if (_selectedToken != null && _contactProfile != null)
                Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: DnaColors.success.withAlpha(20),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: DnaColors.success.withAlpha(50)),
                  ),
                  child: Row(
                    children: [
                      FaIcon(FontAwesomeIcons.circleCheck, color: DnaColors.success, size: 20),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Builder(builder: (_) {
                          final addr = _selectedToken!.getAddress(_contactProfile!);
                          if (addr.length > 20) {
                            return Text(
                              '${addr.substring(0, 12)}...${addr.substring(addr.length - 8)}',
                              style: theme.textTheme.bodySmall?.copyWith(fontFamily: 'monospace'),
                            );
                          }
                          return Text(addr, style: theme.textTheme.bodySmall?.copyWith(fontFamily: 'monospace'));
                        }),
                      ),
                    ],
                  ),
                ),
              const SizedBox(height: 16),

              // Amount input
              TextField(
                controller: _amountController,
                keyboardType: const TextInputType.numberWithOptions(decimal: true),
                decoration: InputDecoration(
                  labelText: 'Amount',
                  hintText: '0.00',
                  suffixText: _selectedToken?.token ?? '',
                  helperText: balance != null ? 'Available: $balance ${_selectedToken?.token ?? ''}' : null,
                ),
                onChanged: (_) => setState(() {}),
              ),
              const SizedBox(height: 8),

              // Max button
              if (maxAmount != null && maxAmount > 0)
                Align(
                  alignment: Alignment.centerRight,
                  child: TextButton(
                    onPressed: () {
                      _amountController.text = maxAmount.toStringAsFixed(
                        maxAmount < 0.01 ? 8 : (maxAmount < 1 ? 4 : 2),
                      );
                      setState(() {});
                    },
                    child: const Text('Max'),
                  ),
                ),
              const SizedBox(height: 16),

              // Transaction speed selector (Cellframe only)
              if (_showSpeedSelector) ...[
                Text('Transaction Speed', style: theme.textTheme.bodySmall),
                const SizedBox(height: 8),
                Row(
                  children: [
                    _buildSpeedChip('Slow', _cellframeValidatorSlow + _cellframeNetworkFee, 0),
                    const SizedBox(width: 8),
                    _buildSpeedChip('Normal', _cellframeValidatorNormal + _cellframeNetworkFee, 1),
                    const SizedBox(width: 8),
                    _buildSpeedChip('Fast', _cellframeValidatorFast + _cellframeNetworkFee, 2),
                  ],
                ),
                const SizedBox(height: 16),
              ],

              // Error display
              if (_sendError != null)
                Container(
                  padding: const EdgeInsets.all(12),
                  margin: const EdgeInsets.only(bottom: 16),
                  decoration: BoxDecoration(
                    color: DnaColors.error.withAlpha(20),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: DnaColors.error.withAlpha(50)),
                  ),
                  child: Row(
                    children: [
                      FaIcon(FontAwesomeIcons.circleExclamation,
                             color: DnaColors.error, size: 16),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          _sendError!,
                          style: TextStyle(color: DnaColors.error, fontSize: 13),
                        ),
                      ),
                    ],
                  ),
                ),

              // Send button
              ElevatedButton(
                onPressed: _canSend() ? _send : null,
                child: _isSending
                    ? const SizedBox(
                        width: 20,
                        height: 20,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : Text('Send ${_selectedToken?.token ?? 'Tokens'}'),
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildSpeedChip(String label, double fee, int speed) {
    final selected = _selectedGasSpeed == speed;
    return Expanded(
      child: GestureDetector(
        onTap: () => setState(() => _selectedGasSpeed = speed),
        child: Container(
          padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 4),
          decoration: BoxDecoration(
            color: selected ? Theme.of(context).colorScheme.primary.withAlpha(30) : Colors.transparent,
            borderRadius: BorderRadius.circular(8),
            border: Border.all(
              color: selected ? Theme.of(context).colorScheme.primary : Theme.of(context).dividerColor,
            ),
          ),
          child: Column(
            children: [
              Text(
                label,
                style: TextStyle(
                  fontWeight: selected ? FontWeight.bold : FontWeight.normal,
                  color: selected ? Theme.of(context).colorScheme.primary : null,
                ),
              ),
              Text(
                '${fee.toStringAsFixed(fee < 0.01 ? 4 : 3)} CELL',
                style: Theme.of(context).textTheme.bodySmall?.copyWith(fontSize: 10),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
```

**Step 5: Build Flutter**

Run: `cd /opt/dna/messenger/dna_messenger_flutter && flutter build linux`
Expected: Clean build.

**Step 6: Commit**

```bash
git add messenger/dna_messenger_flutter/lib/screens/chat/chat_screen.dart
git commit -m "feat: multi-token send from chat (CELL, CPUNK, USDC, USDT, ETH, SOL, TRX)"
```

---

### Task 4: Add i18n Strings for Multi-Token Send Sheet

**MANDATORY**: All user-visible strings must use `AppLocalizations`. Add new keys to both ARB files.

**Files:**
- Modify: `messenger/dna_messenger_flutter/lib/l10n/app_en.arb`
- Modify: `messenger/dna_messenger_flutter/lib/l10n/app_tr.arb`
- Modify: `messenger/dna_messenger_flutter/lib/screens/chat/chat_screen.dart`

**Step 1: Add English strings to `app_en.arb`**

Add these keys (in the `chat` section, after existing `chatMessageDeleted` etc.):

```json
  "chatSendTokens": "Send Tokens",
  "chatSendTokensTo": "to {name}",
  "@chatSendTokensTo": {
    "placeholders": {
      "name": { "type": "String" }
    }
  },
  "chatLookingUpWallets": "Looking up wallet addresses...",
  "chatNoWalletAddresses": "Contact has no wallet addresses in their profile",
  "chatTokenLabel": "Token",
  "chatSendAmount": "Amount",
  "chatSendAvailable": "Available: {balance} {token}",
  "@chatSendAvailable": {
    "placeholders": {
      "balance": { "type": "String" },
      "token": { "type": "String" }
    }
  },
  "chatSendMax": "Max",
  "chatTransactionSpeed": "Transaction Speed",
  "chatSpeedSlow": "Slow",
  "chatSpeedNormal": "Normal",
  "chatSpeedFast": "Fast",
  "chatSendButton": "Send {token}",
  "@chatSendButton": {
    "placeholders": {
      "token": { "type": "String" }
    }
  },
  "chatSentSuccess": "Sent {amount} {token}",
  "@chatSentSuccess": {
    "placeholders": {
      "amount": { "type": "String" },
      "token": { "type": "String" }
    }
  },
  "chatInvalidAmount": "Please enter a valid amount",
  "chatInsufficientBalance": "Insufficient {token} balance",
  "@chatInsufficientBalance": {
    "placeholders": {
      "token": { "type": "String" }
    }
  },
  "chatNoWalletForNetwork": "Contact has no wallet for this network",
```

**Step 2: Add Turkish translations to `app_tr.arb`**

```json
  "chatSendTokens": "Token Gönder",
  "chatSendTokensTo": "{name} kişisine",
  "chatLookingUpWallets": "Cüzdan adresleri aranıyor...",
  "chatNoWalletAddresses": "Kişinin profilinde cüzdan adresi yok",
  "chatTokenLabel": "Token",
  "chatSendAmount": "Miktar",
  "chatSendAvailable": "Kullanılabilir: {balance} {token}",
  "chatSendMax": "Maks",
  "chatTransactionSpeed": "İşlem Hızı",
  "chatSpeedSlow": "Yavaş",
  "chatSpeedNormal": "Normal",
  "chatSpeedFast": "Hızlı",
  "chatSendButton": "{token} Gönder",
  "chatSentSuccess": "{amount} {token} gönderildi",
  "chatInvalidAmount": "Lütfen geçerli bir miktar girin",
  "chatInsufficientBalance": "Yetersiz {token} bakiyesi",
  "chatNoWalletForNetwork": "Kişinin bu ağ için cüzdanı yok",
```

**Step 3: Update `_ChatSendSheet` to use l10n**

In `chat_screen.dart`, in the `_ChatSendSheetState.build()` method, add:
```dart
final l10n = AppLocalizations.of(context);
```

Then replace all hardcoded strings:
- `'Send Tokens'` → `l10n.chatSendTokens`
- `'to ${...}'` → `l10n.chatSendTokensTo(name)`
- `'Looking up wallet addresses...'` → `l10n.chatLookingUpWallets`
- `'Contact has no wallet addresses in their profile'` → `l10n.chatNoWalletAddresses`
- `'Token'` (labelText) → `l10n.chatTokenLabel`
- `'Amount'` → `l10n.chatSendAmount`
- `'Available: $balance ...'` → `l10n.chatSendAvailable(balance, token)`
- `'Max'` → `l10n.chatSendMax`
- `'Transaction Speed'` → `l10n.chatTransactionSpeed`
- `'Slow'`/`'Normal'`/`'Fast'` → `l10n.chatSpeedSlow` / `.chatSpeedNormal` / `.chatSpeedFast`
- `'Send ${token}'` → `l10n.chatSendButton(token)`
- `'Sent $amountStr ${token}'` → `l10n.chatSentSuccess(amountStr, token)`
- `'Please enter a valid amount'` → `l10n.chatInvalidAmount`
- `'Insufficient ${token} balance'` → `l10n.chatInsufficientBalance(token)`
- `'Contact has no wallet for this network'` → `l10n.chatNoWalletForNetwork`

Also add the import at the top of the file if not present:
```dart
import '../../l10n/app_localizations.dart';
```

**Step 4: Build Flutter** (gen-l10n runs automatically)

Run: `cd /opt/dna/messenger/dna_messenger_flutter && flutter build linux`
Expected: Clean build.

**Step 5: Commit**

```bash
git add messenger/dna_messenger_flutter/lib/l10n/ messenger/dna_messenger_flutter/lib/screens/chat/chat_screen.dart
git commit -m "i18n: add localized strings for multi-token send sheet (EN+TR)"
```

---

### Task 5: Version Bump + Final Build Verification

**Files:**
- Modify: `messenger/dna_messenger_flutter/pubspec.yaml` (Flutter version bump)
- Modify: `messenger/include/dna/version.h` (C version bump)

**Step 1: Bump Flutter version**

Current: `v1.0.0-rc12+10362` → bump rc number per project convention.

**Step 2: Bump C library version**

Current: `v0.9.48` → `v0.9.49` (since we changed `dna_engine_wallet.c`).

**Step 3: Build both**

```bash
cd /opt/dna/messenger/build && cmake .. && make -j$(nproc)
cd /opt/dna/messenger/dna_messenger_flutter && flutter build linux
```

**Step 4: Commit**

```bash
git add messenger/dna_messenger_flutter/pubspec.yaml messenger/include/dna/version.h
git commit -m "chore: version bump — lib v0.9.49, app v1.0.0-rc13"
```

---

### Task 6: Update Documentation

**Files:**
- Modify: `messenger/docs/FLUTTER_UI.md` — Document new multi-token send sheet
- Modify: `messenger/docs/functions/engine.md` — Note "Cellframe" network string acceptance
- Modify: `messenger/CLAUDE.md` — Update version numbers in header + checkpoint 8

**Step 1: Update relevant docs**

Add multi-token send documentation, note the Backbone → Cellframe rename.

**Step 2: Commit**

```bash
git add messenger/docs/ messenger/CLAUDE.md
git commit -m "docs: document multi-token chat send and Backbone → Cellframe rename"
```
