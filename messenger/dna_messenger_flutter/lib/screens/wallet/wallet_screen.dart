// Wallet Screen - Wallet list and balances
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_svg/flutter_svg.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../../ffi/dna_engine.dart' show AddressBookEntry, Contact, Transaction, UserProfile, Wallet;
import '../../providers/addressbook_provider.dart';
import '../../providers/providers.dart' hide UserProfile;
import '../../theme/dna_theme.dart';
import 'address_book_screen.dart';
import 'address_dialog.dart';

/// Get the SVG icon path for a token
String? getTokenIconPath(String token) {
  switch (token.toUpperCase()) {
    case 'ETH':
      return 'assets/icons/crypto/eth.svg';
    case 'SOL':
      return 'assets/icons/crypto/sol.svg';
    case 'TRX':
      return 'assets/icons/crypto/trx.svg';
    case 'USDT':
      return 'assets/icons/crypto/usdt.svg';
    case 'CELL':
    case 'CPUNK':
    case 'NYS':
    case 'KEL':
    case 'QEVM':
      return 'assets/icons/crypto/cell.svg';  // CF20 tokens use Cellframe icon
    default:
      return null;
  }
}

/// Convert internal network name to display label
String getNetworkDisplayLabel(String network) {
  switch (network.toLowerCase()) {
    case 'backbone':
    case 'cellframe':
      return 'CF20';
    case 'ethereum':
      return 'ERC20';
    case 'solana':
      return 'SPL';
    case 'tron':
      return 'TRC20';
    default:
      return network;
  }
}

class WalletScreen extends ConsumerWidget {
  final VoidCallback? onMenuPressed;

  const WalletScreen({super.key, this.onMenuPressed});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final wallets = ref.watch(walletsProvider);
    final selectedIndex = ref.watch(selectedWalletIndexProvider);

    return Scaffold(
      appBar: AppBar(
        leading: onMenuPressed != null
            ? IconButton(
                icon: const FaIcon(FontAwesomeIcons.bars),
                onPressed: onMenuPressed,
              )
            : null,
        title: const Text('Wallet'),
        actions: [
          IconButton(
            icon: const FaIcon(FontAwesomeIcons.addressBook),
            onPressed: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const AddressBookScreen()),
            ),
            tooltip: 'Address Book',
          ),
          IconButton(
            icon: const FaIcon(FontAwesomeIcons.arrowsRotate),
            onPressed: () => ref.invalidate(walletsProvider),
            tooltip: 'Refresh',
          ),
        ],
      ),
      body: wallets.when(
        data: (list) => _buildContent(context, ref, list, selectedIndex),
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (error, stack) => _buildError(context, ref, error),
      ),
    );
  }

  Widget _buildContent(
    BuildContext context,
    WidgetRef ref,
    List<Wallet> wallets,
    int selectedIndex,
  ) {
    final theme = Theme.of(context);

    if (wallets.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            FaIcon(
              FontAwesomeIcons.wallet,
              size: 64,
              color: theme.colorScheme.primary.withAlpha(128),
            ),
            const SizedBox(height: 16),
            Text(
              'No wallets yet',
              style: theme.textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            Text(
              'Wallets are derived from your identity',
              style: theme.textTheme.bodySmall,
            ),
          ],
        ),
      );
    }

    return RefreshIndicator(
      onRefresh: () async {
        await ref.read(walletsProvider.notifier).refresh();
        ref.invalidate(allBalancesProvider);
      },
      child: ListView(
        children: [
          // All balances from all wallets combined
          const _AllBalancesSection(),
        ],
      ),
    );
  }

  Widget _buildError(BuildContext context, WidgetRef ref, Object error) {
    final theme = Theme.of(context);

    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            FaIcon(
              FontAwesomeIcons.circleExclamation,
              size: 48,
              color: DnaColors.textWarning,
            ),
            const SizedBox(height: 16),
            Text(
              'Failed to load wallets',
              style: theme.textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            Text(
              error.toString(),
              style: theme.textTheme.bodySmall,
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 16),
            ElevatedButton(
              onPressed: () => ref.invalidate(walletsProvider),
              child: const Text('Retry'),
            ),
          ],
        ),
      ),
    );
  }
}

class _WalletSelector extends StatelessWidget {
  final List<Wallet> wallets;
  final int selectedIndex;
  final ValueChanged<int> onSelected;

  const _WalletSelector({
    required this.wallets,
    required this.selectedIndex,
    required this.onSelected,
  });

  @override
  Widget build(BuildContext context) {
    if (wallets.length <= 1) return const SizedBox.shrink();

    final theme = Theme.of(context);

    return Container(
      height: 64,
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      padding: const EdgeInsets.all(6),
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        borderRadius: BorderRadius.circular(28),
      ),
      child: Row(
        children: List.generate(wallets.length, (index) {
          final wallet = wallets[index];
          final isSelected = index == selectedIndex;

          return Expanded(
            child: GestureDetector(
              onTap: () => onSelected(index),
              child: AnimatedContainer(
                duration: const Duration(milliseconds: 200),
                curve: Curves.easeInOut,
                decoration: BoxDecoration(
                  color: isSelected ? theme.colorScheme.primary : Colors.transparent,
                  borderRadius: BorderRadius.circular(24),
                ),
                child: Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 6),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      AnimatedDefaultTextStyle(
                        duration: const Duration(milliseconds: 200),
                        style: theme.textTheme.bodyMedium!.copyWith(
                          color: isSelected
                              ? theme.colorScheme.onPrimary
                              : theme.colorScheme.onSurface.withAlpha(180),
                          fontWeight: isSelected ? FontWeight.w600 : FontWeight.normal,
                        ),
                        child: Text(
                          wallet.name.isNotEmpty ? wallet.name : 'Wallet ${index + 1}',
                          overflow: TextOverflow.ellipsis,
                          maxLines: 1,
                        ),
                      ),
                      const SizedBox(height: 2),
                      AnimatedDefaultTextStyle(
                        duration: const Duration(milliseconds: 200),
                        style: theme.textTheme.labelSmall!.copyWith(
                          color: isSelected
                              ? theme.colorScheme.onPrimary.withAlpha(200)
                              : theme.colorScheme.onSurface.withAlpha(120),
                          fontSize: 10,
                        ),
                        child: Text(
                          _getSigTypeName(wallet.sigType),
                          overflow: TextOverflow.ellipsis,
                          maxLines: 1,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          );
        }),
      ),
    );
  }

  String _getSigTypeName(int sigType) {
    switch (sigType) {
      case 0:
      case 4:
        return 'Dilithium';
      case 1:
        return 'Picnic';
      case 2:
        return 'Bliss';
      case 3:
        return 'Tesla';
      case 100:
        return 'ETH';
      case 101:
        return 'SOL';
      default:
        return 'Type $sigType';
    }
  }
}

class _WalletCard extends StatelessWidget {
  final Wallet wallet;

  const _WalletCard({required this.wallet});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 16),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                FaIcon(
                  FontAwesomeIcons.wallet,
                  color: theme.colorScheme.primary,
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    wallet.name.isNotEmpty ? wallet.name : 'Primary Wallet',
                    style: theme.textTheme.titleMedium,
                  ),
                ),
                if (wallet.isProtected)
                  Tooltip(
                    message: 'Protected wallet',
                    child: FaIcon(
                      FontAwesomeIcons.lock,
                      size: 20,
                      color: theme.colorScheme.secondary,
                    ),
                  ),
              ],
            ),
            const SizedBox(height: 16),
            Text(
              'Address',
              style: theme.textTheme.labelSmall,
            ),
            const SizedBox(height: 4),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: theme.scaffoldBackgroundColor,
                borderRadius: BorderRadius.circular(8),
              ),
              child: Row(
                children: [
                  Expanded(
                    child: Text(
                      wallet.address,
                      style: theme.textTheme.bodySmall?.copyWith(
                        fontFamily: 'monospace',
                      ),
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                  IconButton(
                    icon: const FaIcon(FontAwesomeIcons.copy, size: 18),
                    onPressed: () {
                      Clipboard.setData(ClipboardData(text: wallet.address));
                      ScaffoldMessenger.of(context).showSnackBar(
                        const SnackBar(
                          content: Text('Address copied'),
                          duration: Duration(seconds: 2),
                        ),
                      );
                    },
                    tooltip: 'Copy address',
                  ),
                ],
              ),
            ),
            const SizedBox(height: 8),
            Text(
              'Signature: ${_getSigTypeName(wallet.sigType)}',
              style: theme.textTheme.labelSmall,
            ),
          ],
        ),
      ),
    );
  }

  String _getSigTypeName(int sigType) {
    switch (sigType) {
      case 0:
      case 4:
        return 'Dilithium (Post-Quantum)';
      case 1:
        return 'Picnic';
      case 2:
        return 'Bliss';
      case 3:
        return 'Tesla';
      case 100:
        return 'ETH (secp256k1)';
      case 101:
        return 'SOL (Ed25519)';
      default:
        return 'Type $sigType';
    }
  }
}

class _AllBalancesSection extends ConsumerWidget {
  const _AllBalancesSection();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final allBalances = ref.watch(allBalancesProvider);
    final theme = Theme.of(context);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        allBalances.when(
          data: (list) => list.isEmpty
              ? Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 16),
                  child: Text(
                    'No balances',
                    style: theme.textTheme.bodySmall,
                  ),
                )
              : Column(
                  children: list.map((wb) => _BalanceTile(
                    walletBalance: wb,
                  )).toList(),
                ),
          loading: () => const Padding(
            padding: EdgeInsets.all(16),
            child: Center(child: CircularProgressIndicator()),
          ),
          error: (error, _) => Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16),
            child: Text(
              'Failed to load: $error',
              style: TextStyle(color: DnaColors.textWarning),
            ),
          ),
        ),
      ],
    );
  }
}

class _BalanceTile extends ConsumerWidget {
  final WalletBalance walletBalance;

  const _BalanceTile({
    required this.walletBalance,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final balance = walletBalance.balance;

    final iconPath = getTokenIconPath(balance.token);

    return ListTile(
      leading: iconPath != null
          ? SizedBox(
              width: 40,
              height: 40,
              child: SvgPicture.asset(
                iconPath,
                fit: BoxFit.contain,
              ),
            )
          : CircleAvatar(
              backgroundColor: _getTokenColor(balance.token).withAlpha(51),
              child: Text(
                balance.token.isNotEmpty ? balance.token[0].toUpperCase() : '?',
                style: TextStyle(
                  color: _getTokenColor(balance.token),
                  fontWeight: FontWeight.bold,
                ),
              ),
            ),
      title: Text(balance.token),
      subtitle: Text(getNetworkDisplayLabel(balance.network)),
      trailing: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 150),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Flexible(
              child: Text(
                balance.balance,
                style: theme.textTheme.titleMedium?.copyWith(
                  fontWeight: FontWeight.bold,
                ),
                overflow: TextOverflow.ellipsis,
              ),
            ),
            const SizedBox(width: 4),
            FaIcon(
              FontAwesomeIcons.chevronRight,
              color: theme.colorScheme.primary.withAlpha(128),
              size: 20,
            ),
          ],
        ),
      ),
      onTap: () => _showTokenDetails(context, ref),
    );
  }

  void _showTokenDetails(BuildContext context, WidgetRef ref) {
    final balance = walletBalance.balance;
    final network = balance.network == 'Ethereum' ? 'Ethereum' : 'Backbone';

    // Invalidate to fetch fresh data when opening
    ref.invalidate(transactionsProvider((walletIndex: walletBalance.walletIndex, network: network)));
    ref.invalidate(balancesProvider(walletBalance.walletIndex));

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      builder: (context) => _TokenDetailSheet(
        walletIndex: walletBalance.walletIndex,
        walletAddress: walletBalance.wallet.address,
        token: balance.token,
        network: balance.network,
        initialBalance: balance.balance,
      ),
    );
  }

  Color _getTokenColor(String token) {
    switch (token.toUpperCase()) {
      case 'CPUNK':
        return const Color(0xFF00D4AA); // Cyan/Teal for CPUNK
      case 'CELL':
        return const Color(0xFF6B4CE6); // Purple for CELL
      case 'ETH':
        return const Color(0xFF627EEA); // Ethereum blue
      case 'SOL':
        return const Color(0xFF9945FF); // Solana purple
      default:
        return DnaColors.textInfo;
    }
  }
}

class _ActionButtons extends ConsumerWidget {
  final Wallet wallet;
  final int walletIndex;

  const _ActionButtons({required this.wallet, required this.walletIndex});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16),
      child: Row(
        children: [
          Expanded(
            child: OutlinedButton.icon(
              onPressed: () => _showReceive(context),
              icon: const FaIcon(FontAwesomeIcons.arrowDown),
              label: const Text('Receive'),
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: ElevatedButton.icon(
              onPressed: () => _showSend(context, ref),
              icon: const FaIcon(FontAwesomeIcons.arrowUp),
              label: const Text('Send'),
            ),
          ),
        ],
      ),
    );
  }

  void _showReceive(BuildContext context) {
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
              ElevatedButton.icon(
                onPressed: () {
                  Clipboard.setData(ClipboardData(text: wallet.address));
                  final messenger = ScaffoldMessenger.of(context);
                  Navigator.pop(context);
                  messenger.showSnackBar(
                    const SnackBar(content: Text('Address copied')),
                  );
                },
                icon: const FaIcon(FontAwesomeIcons.copy),
                label: const Text('Copy Address'),
              ),
            ],
          ),
        ),
      ),
    );
  }

  void _showSend(BuildContext context, WidgetRef ref) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      builder: (context) => _SendSheet(
        walletIndex: walletIndex,
      ),
    );
  }
}

class _SendSheet extends ConsumerStatefulWidget {
  final int walletIndex;
  final String? preselectedToken;
  final String? preselectedNetwork;
  final String? availableBalance;

  const _SendSheet({
    required this.walletIndex,
    this.preselectedToken,
    this.preselectedNetwork,
    this.availableBalance,
  });

  @override
  ConsumerState<_SendSheet> createState() => _SendSheetState();
}

class _SendSheetState extends ConsumerState<_SendSheet> {
  final _recipientController = TextEditingController();
  final _amountController = TextEditingController();
  late String _selectedToken;
  late String _selectedNetwork;
  int _selectedGasSpeed = 1; // 0=slow, 1=normal, 2=fast
  bool _isSending = false;

  // DNA fingerprint resolution
  String? _resolvedAddress;      // Resolved wallet address from fingerprint
  String? _resolvedContactName;  // Display name if resolved from fingerprint
  bool _isResolving = false;     // Loading state during DHT lookup
  String? _resolveError;         // Error message if resolution failed
  int _resolveRequestId = 0;     // Counter to handle race conditions in async lookups

  // Gas fee estimates for ETH
  String? _gasFee0; // slow
  String? _gasFee1; // normal
  String? _gasFee2; // fast

  // Backbone network fees (validator fee varies by speed, network fee is fixed)
  static const double _backboneNetworkFee = 0.002;
  static const double _backboneValidatorSlow = 0.0001;   // slow
  static const double _backboneValidatorNormal = 0.01;   // normal
  static const double _backboneValidatorFast = 0.05;     // fast

  // ETH default gas fees (31500 gas * typical gwei prices)
  static const double _ethDefaultGasSlow = 0.0012;   // ~20 gwei
  static const double _ethDefaultGasNormal = 0.0015; // ~25 gwei
  static const double _ethDefaultGasFast = 0.00225;  // ~35 gwei

  /// Get current balance for selected token/network from provider
  String? _getCurrentBalance() {
    // First try the preselected balance if token/network match
    if (widget.availableBalance != null &&
        widget.preselectedToken == _selectedToken &&
        widget.preselectedNetwork == _selectedNetwork) {
      return widget.availableBalance;
    }

    // Otherwise fetch from balances provider
    final balancesAsync = ref.watch(balancesProvider(widget.walletIndex));
    return balancesAsync.whenOrNull(
      data: (balances) {
        for (final b in balances) {
          if (b.token == _selectedToken && b.network == _selectedNetwork) {
            return b.balance;
          }
        }
        return null;
      },
    );
  }

  /// Calculate max sendable amount after fees
  double? _calculateMaxAmount() {
    final balanceStr = _getCurrentBalance();
    if (balanceStr == null || balanceStr.isEmpty) return null;

    final balance = double.tryParse(balanceStr);
    if (balance == null || balance <= 0) return null;

    if (_selectedNetwork == 'Ethereum') {
      // ETH: only subtract gas fee when sending ETH (native token)
      if (_selectedToken == 'ETH') {
        double fee;
        switch (_selectedGasSpeed) {
          case 0:
            fee = double.tryParse(_gasFee0 ?? '') ?? _ethDefaultGasSlow;
            break;
          case 1:
            fee = double.tryParse(_gasFee1 ?? '') ?? _ethDefaultGasNormal;
            break;
          case 2:
            fee = double.tryParse(_gasFee2 ?? '') ?? _ethDefaultGasFast;
            break;
          default:
            fee = _ethDefaultGasNormal;
        }
        final max = balance - fee;
        return max > 0 ? max : 0;
      }
      // For ERC-20 tokens, no fee subtraction (gas paid in ETH)
      return balance;
    } else {
      // Backbone (Cellframe): only subtract fee when sending CELL (native token)
      // CPUNK and other tokens: fees are paid in CELL, not the token itself
      if (_selectedToken == 'CELL') {
        double validatorFee;
        switch (_selectedGasSpeed) {
          case 0:
            validatorFee = _backboneValidatorSlow;
            break;
          case 1:
            validatorFee = _backboneValidatorNormal;
            break;
          case 2:
            validatorFee = _backboneValidatorFast;
            break;
          default:
            validatorFee = _backboneValidatorNormal;
        }
        final totalFee = validatorFee + _backboneNetworkFee;
        final max = balance - totalFee;
        return max > 0 ? max : 0;
      }
      // For other tokens like CPUNK, full balance is sendable
      return balance;
    }
  }

  /// Format max amount for display
  String _formatMaxAmount(double? max) {
    if (max == null) return '-';
    if (max <= 0) return '0';
    // Use 8 decimals for small amounts, 4 for medium, 2 for large
    if (max < 0.01) {
      return max.toStringAsFixed(8);
    } else if (max < 1.0) {
      return max.toStringAsFixed(4);
    } else {
      return max.toStringAsFixed(2);
    }
  }

  @override
  void initState() {
    super.initState();
    _selectedToken = widget.preselectedToken ?? 'CPUNK';
    _selectedNetwork = widget.preselectedNetwork ?? 'Backbone';
    if (_selectedNetwork == 'Ethereum') {
      _fetchGasEstimates();
    }
  }

  Future<void> _fetchGasEstimates() async {
    final engine = await ref.read(engineProvider.future);
    final est0 = engine.estimateEthGas(0);
    final est1 = engine.estimateEthGas(1);
    final est2 = engine.estimateEthGas(2);
    if (mounted) {
      setState(() {
        _gasFee0 = est0?.feeEth;
        _gasFee1 = est1?.feeEth;
        _gasFee2 = est2?.feeEth;
      });
    }
  }

  @override
  void dispose() {
    _recipientController.dispose();
    _amountController.dispose();
    super.dispose();
  }

  /// Check if input looks like a DNA fingerprint (128 hex chars)
  bool _isFingerprint(String input) {
    if (input.length != 128) return false;
    return RegExp(r'^[0-9a-fA-F]{128}$').hasMatch(input);
  }

  /// Check if input looks like a DNA identity name (3-20 alphanumeric chars)
  bool _isDnaName(String input) {
    if (input.length < 3 || input.length > 20) return false;
    return RegExp(r'^[a-zA-Z0-9_]+$').hasMatch(input);
  }

  /// Get the appropriate wallet address from profile based on selected network
  String? _getWalletAddressForNetwork(UserProfile profile) {
    final network = _selectedNetwork.toLowerCase();
    if (network == 'ethereum') {
      return profile.eth.isNotEmpty ? profile.eth : null;
    } else if (network == 'solana') {
      return profile.sol.isNotEmpty ? profile.sol : null;
    } else if (network == 'tron') {
      return profile.trx.isNotEmpty ? profile.trx : null;
    } else {
      // Backbone (default)
      return profile.backbone.isNotEmpty ? profile.backbone : null;
    }
  }

  /// Get network-friendly name for error messages
  String _getNetworkWalletName() {
    final network = _selectedNetwork.toLowerCase();
    if (network == 'ethereum') {
      return 'ETH';
    } else if (network == 'solana') {
      return 'SOL';
    } else if (network == 'tron') {
      return 'TRX';
    } else {
      return 'Backbone';
    }
  }

  /// Resolve DNA identity (name or fingerprint) to wallet address
  Future<void> _resolveDnaIdentity(String input) async {
    // Increment request ID to track this specific request
    final thisRequestId = ++_resolveRequestId;

    setState(() {
      _isResolving = true;
      _resolveError = null;
      _resolvedAddress = null;
      _resolvedContactName = null;
    });

    try {
      final engine = await ref.read(engineProvider.future);
      String fingerprint = input;
      String? displayName;

      // If it's a name, first resolve to fingerprint
      if (_isDnaName(input) && !_isFingerprint(input)) {
        final fp = await engine.lookupName(input);
        if (!mounted || thisRequestId != _resolveRequestId) return;

        if (fp.isEmpty) {
          setState(() {
            _isResolving = false;
            _resolveError = 'Identity "$input" not found';
          });
          return;
        }
        fingerprint = fp;
        displayName = input;
      }

      // Now lookup the profile to get wallet address
      final profile = await engine.lookupProfile(fingerprint);

      if (!mounted || thisRequestId != _resolveRequestId) return;

      if (profile == null) {
        setState(() {
          _isResolving = false;
          _resolveError = 'Profile not found in DHT';
        });
        return;
      }

      // Get the appropriate wallet address for the selected network
      final walletAddress = _getWalletAddressForNetwork(profile);

      if (walletAddress == null) {
        setState(() {
          _isResolving = false;
          _resolveError = 'Contact has no ${_getNetworkWalletName()} wallet address';
        });
        return;
      }

      setState(() {
        _isResolving = false;
        _resolvedAddress = walletAddress;
        _resolvedContactName = displayName ??
            (profile.displayName.isNotEmpty
                ? profile.displayName
                : '${fingerprint.substring(0, 8)}...');
      });
    } catch (e) {
      if (!mounted || thisRequestId != _resolveRequestId) return;
      setState(() {
        _isResolving = false;
        _resolveError = 'Could not resolve address';
      });
    }
  }

  /// Handle recipient input changes
  void _onRecipientChanged(String value) {
    final trimmed = value.trim();

    // Clear previous resolution state
    setState(() {
      _resolvedAddress = null;
      _resolvedContactName = null;
      _resolveError = null;
    });

    // Check if it's a fingerprint or DNA name that needs resolution
    if (_isFingerprint(trimmed) || _isDnaName(trimmed)) {
      _resolveDnaIdentity(trimmed);
    }
  }

  /// Show contact picker dialog
  Future<void> _showContactPicker() async {
    final contacts = await ref.read(contactsProvider.future);

    if (!mounted) return;

    // Filter contacts that have wallet addresses (we'll resolve them)
    final result = await showModalBottomSheet<Contact>(
      context: context,
      isScrollControlled: true,
      builder: (context) => DraggableScrollableSheet(
        initialChildSize: 0.6,
        minChildSize: 0.3,
        maxChildSize: 0.9,
        expand: false,
        builder: (context, scrollController) => Column(
          children: [
            Padding(
              padding: const EdgeInsets.all(16),
              child: Row(
                children: [
                  Text(
                    'Select Contact',
                    style: Theme.of(context).textTheme.titleLarge,
                  ),
                  const Spacer(),
                  IconButton(
                    icon: const FaIcon(FontAwesomeIcons.xmark),
                    onPressed: () => Navigator.pop(context),
                  ),
                ],
              ),
            ),
            const Divider(height: 1),
            Expanded(
              child: contacts.isEmpty
                  ? const Center(child: Text('No contacts'))
                  : ListView.builder(
                      controller: scrollController,
                      itemCount: contacts.length,
                      itemBuilder: (context, index) {
                        final contact = contacts[index];
                        return ListTile(
                          leading: CircleAvatar(
                            backgroundColor: DnaColors.primary.withAlpha(50),
                            child: Text(
                              contact.displayName.isNotEmpty
                                  ? contact.displayName[0].toUpperCase()
                                  : '?',
                              style: const TextStyle(color: DnaColors.primary),
                            ),
                          ),
                          title: Text(contact.displayName.isNotEmpty
                              ? contact.displayName
                              : '${contact.fingerprint.substring(0, 16)}...'),
                          subtitle: Text(
                            '${contact.fingerprint.substring(0, 16)}...',
                            style: Theme.of(context).textTheme.bodySmall,
                          ),
                          onTap: () => Navigator.pop(context, contact),
                        );
                      },
                    ),
            ),
          ],
        ),
      ),
    );

    if (result != null && mounted) {
      // Set the fingerprint and resolve it
      _recipientController.text = result.fingerprint;
      _resolveDnaIdentity(result.fingerprint);
    }
  }

  /// Get the actual address to send to
  String get _effectiveRecipient {
    return _resolvedAddress ?? _recipientController.text.trim();
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: EdgeInsets.only(
        bottom: MediaQuery.of(context).viewInsets.bottom,
      ),
      child: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Text(
                'Send',
                style: Theme.of(context).textTheme.titleLarge,
              ),
              const SizedBox(height: 16),
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Expanded(
                    child: TextField(
                      controller: _recipientController,
                      decoration: InputDecoration(
                        labelText: 'Recipient',
                        hintText: 'Address or DNA fingerprint',
                        suffixIcon: _isResolving
                            ? const Padding(
                                padding: EdgeInsets.all(12),
                                child: SizedBox(
                                  width: 20,
                                  height: 20,
                                  child: CircularProgressIndicator(strokeWidth: 2),
                                ),
                              )
                            : null,
                      ),
                      onChanged: _onRecipientChanged,
                    ),
                  ),
                  const SizedBox(width: 8),
                  Padding(
                    padding: const EdgeInsets.only(top: 8),
                    child: IconButton(
                      icon: const FaIcon(FontAwesomeIcons.addressBook),
                      tooltip: 'Select contact',
                      onPressed: _showContactPicker,
                    ),
                  ),
                ],
              ),
              // Resolution status indicator
              if (_resolvedAddress != null)
                Padding(
                  padding: const EdgeInsets.only(top: 4),
                  child: Row(
                    children: [
                      FaIcon(FontAwesomeIcons.circleCheck, size: 16, color: DnaColors.textSuccess),
                      const SizedBox(width: 4),
                      Expanded(
                        child: Text(
                          'Resolved: $_resolvedContactName (${_resolvedAddress!.substring(0, 12)}...)',
                          style: TextStyle(
                            fontSize: 12,
                            color: DnaColors.textSuccess,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              if (_resolveError != null)
                Padding(
                  padding: const EdgeInsets.only(top: 4),
                  child: Row(
                    children: [
                      FaIcon(FontAwesomeIcons.circleExclamation, size: 16, color: DnaColors.textWarning),
                      const SizedBox(width: 4),
                      Text(
                        _resolveError!,
                        style: TextStyle(
                          fontSize: 12,
                          color: DnaColors.textWarning,
                        ),
                      ),
                    ],
                  ),
                ),
              const SizedBox(height: 12),
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Expanded(
                    child: TextField(
                      controller: _amountController,
                      decoration: InputDecoration(
                        labelText: 'Amount',
                        hintText: '0.00',
                        suffixText: _selectedToken,
                      ),
                      keyboardType: const TextInputType.numberWithOptions(decimal: true),
                      onChanged: (_) => setState(() {}),
                    ),
                  ),
                  const SizedBox(width: 8),
                  Column(
                    children: [
                      const SizedBox(height: 8), // Align with TextField
                      OutlinedButton(
                        onPressed: _getCurrentBalance() != null ? () {
                          final max = _calculateMaxAmount();
                          if (max != null && max > 0) {
                            _amountController.text = _formatMaxAmount(max);
                            setState(() {});
                          }
                        } : null,
                        style: OutlinedButton.styleFrom(
                          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                          minimumSize: const Size(50, 36),
                        ),
                        child: const Text('Max'),
                      ),
                      const SizedBox(height: 4),
                      // Show max amount below button
                      if (_getCurrentBalance() != null)
                        Text(
                          'Max: ${_formatMaxAmount(_calculateMaxAmount())} $_selectedToken',
                          style: Theme.of(context).textTheme.labelSmall?.copyWith(
                            color: Theme.of(context).colorScheme.primary.withAlpha(179),
                          ),
                        ),
                    ],
                  ),
                ],
              ),
              const SizedBox(height: 12),
              Row(
                children: [
                  Expanded(
                    child: DropdownButtonFormField<String>(
                      value: _selectedToken,
                      decoration: const InputDecoration(labelText: 'Token'),
                      items: _getTokenItems(),
                      onChanged: (v) => setState(() => _selectedToken = v ?? 'CPUNK'),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: DropdownButtonFormField<String>(
                      value: _selectedNetwork,
                      decoration: const InputDecoration(labelText: 'Network'),
                      items: _getNetworkItems(),
                      onChanged: (v) {
                        setState(() => _selectedNetwork = v ?? 'Backbone');
                        // Re-resolve if there's a DNA identity in the input
                        final input = _recipientController.text.trim();
                        if (_isFingerprint(input) || _isDnaName(input)) {
                          _resolveDnaIdentity(input);
                        }
                      },
                    ),
                  ),
                ],
              ),
              // Gas speed selector for Ethereum
              if (_selectedNetwork == 'Ethereum') ...[
                const SizedBox(height: 16),
                Text(
                  'Transaction Speed (Gas Fee)',
                  style: Theme.of(context).textTheme.bodySmall,
                ),
                const SizedBox(height: 8),
                Row(
                  children: [
                    _GasSpeedChip(
                      label: 'Slow',
                      sublabel: _gasFee0 != null ? '${_gasFee0!} ETH' : '0.8x',
                      selected: _selectedGasSpeed == 0,
                      onSelected: () => setState(() => _selectedGasSpeed = 0),
                    ),
                    const SizedBox(width: 8),
                    _GasSpeedChip(
                      label: 'Normal',
                      sublabel: _gasFee1 != null ? '${_gasFee1!} ETH' : '1.0x',
                      selected: _selectedGasSpeed == 1,
                      onSelected: () => setState(() => _selectedGasSpeed = 1),
                    ),
                    const SizedBox(width: 8),
                    _GasSpeedChip(
                      label: 'Fast',
                      sublabel: _gasFee2 != null ? '${_gasFee2!} ETH' : '1.5x',
                      selected: _selectedGasSpeed == 2,
                      onSelected: () => setState(() => _selectedGasSpeed = 2),
                    ),
                  ],
                ),
              ],
              // Transaction speed selector for Backbone (Cellframe)
              if (_selectedNetwork == 'Backbone') ...[
                const SizedBox(height: 16),
                Text(
                  'Transaction Speed (Validator Fee)',
                  style: Theme.of(context).textTheme.bodySmall,
                ),
                const SizedBox(height: 8),
                Row(
                  children: [
                    _GasSpeedChip(
                      label: 'Slow',
                      sublabel: '${(_backboneValidatorSlow + _backboneNetworkFee).toStringAsFixed(4)} CELL',
                      selected: _selectedGasSpeed == 0,
                      onSelected: () => setState(() => _selectedGasSpeed = 0),
                    ),
                    const SizedBox(width: 8),
                    _GasSpeedChip(
                      label: 'Normal',
                      sublabel: '${(_backboneValidatorNormal + _backboneNetworkFee).toStringAsFixed(3)} CELL',
                      selected: _selectedGasSpeed == 1,
                      onSelected: () => setState(() => _selectedGasSpeed = 1),
                    ),
                    const SizedBox(width: 8),
                    _GasSpeedChip(
                      label: 'Fast',
                      sublabel: '${(_backboneValidatorFast + _backboneNetworkFee).toStringAsFixed(3)} CELL',
                      selected: _selectedGasSpeed == 2,
                      onSelected: () => setState(() => _selectedGasSpeed = 2),
                    ),
                  ],
                ),
              ],
              const SizedBox(height: 16),
              ElevatedButton(
                onPressed: _canSend() ? _send : null,
                child: _isSending
                    ? const SizedBox(
                        width: 20,
                        height: 20,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Text('Send'),
              ),
            ],
          ),
        ),
      ),
    );
  }

  List<DropdownMenuItem<String>> _getTokenItems() {
    // If ETH is preselected, show ETH option
    if (_selectedToken.toUpperCase() == 'ETH') {
      return const [
        DropdownMenuItem(value: 'ETH', child: Text('ETH')),
      ];
    }
    // If SOL is preselected, show SOL option
    if (_selectedToken.toUpperCase() == 'SOL') {
      return const [
        DropdownMenuItem(value: 'SOL', child: Text('SOL')),
      ];
    }
    // If TRX is preselected, show TRX option
    if (_selectedToken.toUpperCase() == 'TRX') {
      return const [
        DropdownMenuItem(value: 'TRX', child: Text('TRX')),
      ];
    }
    // Default: Cellframe tokens
    return const [
      DropdownMenuItem(value: 'CPUNK', child: Text('CPUNK')),
      DropdownMenuItem(value: 'CELL', child: Text('CELL')),
    ];
  }

  List<DropdownMenuItem<String>> _getNetworkItems() {
    final network = _selectedNetwork.toLowerCase();
    // If Ethereum network, show only Ethereum
    if (network == 'ethereum') {
      return [
        DropdownMenuItem(value: _selectedNetwork, child: const Text('ERC20')),
      ];
    }
    // If Solana network, show only Solana
    if (network == 'solana') {
      return [
        DropdownMenuItem(value: _selectedNetwork, child: const Text('SPL')),
      ];
    }
    // If Tron network, show only Tron
    if (network == 'tron') {
      return [
        DropdownMenuItem(value: _selectedNetwork, child: const Text('TRC20')),
      ];
    }
    // Default: Backbone (Cellframe) network
    return [
      DropdownMenuItem(value: _selectedNetwork, child: const Text('CF20')),
    ];
  }

  bool _canSend() {
    if (_isSending || _isResolving) return false;
    if (_amountController.text.trim().isEmpty) return false;

    final input = _recipientController.text.trim();
    if (input.isEmpty) return false;

    // If it's a fingerprint or DNA name, must be resolved successfully
    if (_isFingerprint(input) || _isDnaName(input)) {
      return _resolvedAddress != null && _resolveError == null;
    }

    // Otherwise, assume it's a direct address
    return true;
  }

  Future<void> _send() async {
    setState(() => _isSending = true);

    // Capture values before async gap
    final recipientAddress = _effectiveRecipient;
    final network = _selectedNetwork.toLowerCase() == 'ethereum' ? 'ethereum' :
                    _selectedNetwork.toLowerCase() == 'solana' ? 'solana' :
                    _selectedNetwork.toLowerCase() == 'tron' ? 'tron' : 'backbone';

    try {
      await ref.read(walletsProvider.notifier).sendTokens(
        walletIndex: widget.walletIndex,
        recipientAddress: recipientAddress,
        amount: _amountController.text.trim(),
        token: _selectedToken,
        network: _selectedNetwork,
        gasSpeed: _selectedGasSpeed,
      );

      if (mounted) {
        Navigator.pop(context);
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Transaction submitted successfully')),
        );

        // After successful send, check if address should be saved
        // Skip if this was a DNA fingerprint/name resolution
        if (_resolvedAddress == null) {
          _promptSaveAddress(recipientAddress, network);
        }
      }
    } catch (e) {
      if (mounted) {
        setState(() => _isSending = false);
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to send: $e'),
            backgroundColor: DnaColors.snackbarError,
          ),
        );
      }
    }
  }

  /// Prompt user to save address if it's new
  void _promptSaveAddress(String address, String network) async {
    try {
      final engine = await ref.read(engineProvider.future);

      // Check if address already exists
      final exists = engine.addressExists(address, network);
      if (exists) {
        // Address exists - increment usage silently
        final entry = engine.lookupAddress(address, network);
        if (entry != null) {
          engine.incrementAddressUsage(entry.id);
        }
        return;
      }

      // New address - prompt to save
      if (!mounted) return;
      final shouldSave = await showDialog<bool>(
        context: context,
        builder: (context) => AlertDialog(
          title: const Text('Save Address?'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text('Would you like to save this address to your address book?'),
              const SizedBox(height: 12),
              Text(
                '${address.substring(0, 10)}...${address.substring(address.length - 8)}',
                style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              ),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: const Text('No thanks'),
            ),
            ElevatedButton(
              onPressed: () => Navigator.pop(context, true),
              child: const Text('Save'),
            ),
          ],
        ),
      );

      if (shouldSave == true && mounted) {
        // Show add address dialog
        final result = await showDialog<AddressDialogResult>(
          context: context,
          builder: (context) => AddressDialog.prefilled(
            address: address,
            network: network,
          ),
        );

        if (result != null) {
          await ref.read(addressBookProvider.notifier).addAddress(
            address: result.address,
            label: result.label,
            network: result.network,
            notes: result.notes,
          );
          if (mounted) {
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(content: Text('Saved "${result.label}" to address book')),
            );
          }
        }
      }
    } catch (e) {
      // Silently ignore errors - save prompt is optional
    }
  }
}

/// Token detail sheet - shows address, send button, and history
class _TokenDetailSheet extends ConsumerWidget {
  final int walletIndex;
  final String walletAddress;
  final String token;
  final String network;
  final String initialBalance;

  const _TokenDetailSheet({
    required this.walletIndex,
    required this.walletAddress,
    required this.token,
    required this.network,
    required this.initialBalance,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final transactionsAsync = ref.watch(
      transactionsProvider((walletIndex: walletIndex, network: network == 'Ethereum' ? 'Ethereum' : 'Backbone')),
    );
    // Watch balances to get updated value after refresh
    final balancesAsync = ref.watch(balancesProvider(walletIndex));
    final balance = balancesAsync.whenOrNull(
      data: (balances) => balances
          .where((b) => b.token == token && b.network == network)
          .map((b) => b.balance)
          .firstOrNull,
    ) ?? initialBalance;
    final theme = Theme.of(context);

    return DraggableScrollableSheet(
      initialChildSize: 0.85,
      minChildSize: 0.5,
      maxChildSize: 0.95,
      expand: false,
      builder: (context, scrollController) {
        return SafeArea(
          child: Column(
            children: [
              // Handle bar
              Container(
                margin: const EdgeInsets.only(top: 8),
                width: 40,
                height: 4,
                decoration: BoxDecoration(
                  color: theme.dividerColor,
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
              // Header with token info
              Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  children: [
                    Builder(
                      builder: (context) {
                        final iconPath = getTokenIconPath(token);
                        return Row(
                          children: [
                            iconPath != null
                                ? SizedBox(
                                    width: 48,
                                    height: 48,
                                    child: SvgPicture.asset(
                                      iconPath,
                                      fit: BoxFit.contain,
                                    ),
                                  )
                                : CircleAvatar(
                                    backgroundColor: _getTokenColor(token).withAlpha(51),
                                    radius: 24,
                                    child: Text(
                                      token.isNotEmpty ? token[0].toUpperCase() : '?',
                                      style: TextStyle(
                                        color: _getTokenColor(token),
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
                                    style: theme.textTheme.headlineSmall?.copyWith(
                                      fontWeight: FontWeight.bold,
                                    ),
                                  ),
                                  Text(
                                    getNetworkDisplayLabel(network),
                                    style: theme.textTheme.bodySmall,
                                  ),
                                ],
                              ),
                            ),
                            IconButton(
                              icon: const FaIcon(FontAwesomeIcons.arrowsRotate),
                              onPressed: () {
                                ref.invalidate(balancesProvider(walletIndex));
                                ref.invalidate(transactionsProvider((walletIndex: walletIndex, network: network == 'Ethereum' ? 'Ethereum' : 'Backbone')));
                              },
                              tooltip: 'Refresh',
                            ),
                          ],
                        );
                      },
                    ),
                    const SizedBox(height: 16),
                    // Address section
                    Container(
                      width: double.infinity,
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: theme.colorScheme.surface,
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(color: theme.dividerColor),
                      ),
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
                          Row(
                            children: [
                              Expanded(
                                child: Text(
                                  walletAddress,
                                  style: theme.textTheme.bodySmall?.copyWith(
                                    fontFamily: 'monospace',
                                  ),
                                  maxLines: 2,
                                  overflow: TextOverflow.ellipsis,
                                ),
                              ),
                              IconButton(
                                icon: const FaIcon(FontAwesomeIcons.copy, size: 18),
                                onPressed: () {
                                  Clipboard.setData(ClipboardData(text: walletAddress));
                                  ScaffoldMessenger.of(context).showSnackBar(
                                    const SnackBar(
                                      content: Text('Address copied'),
                                      duration: Duration(seconds: 2),
                                    ),
                                  );
                                },
                                tooltip: 'Copy address',
                                padding: EdgeInsets.zero,
                                constraints: const BoxConstraints(),
                              ),
                            ],
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 12),
                    // Send button
                    SizedBox(
                      width: double.infinity,
                      child: ElevatedButton.icon(
                        onPressed: () => _showSend(context, ref, balance),
                        icon: const FaIcon(FontAwesomeIcons.arrowUp),
                        label: Text('Send $token'),
                      ),
                    ),
                  ],
                ),
              ),
              const Divider(height: 1),
              // Transaction history header
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                child: Row(
                  children: [
                    Text(
                      'Transaction History',
                      style: theme.textTheme.titleSmall?.copyWith(
                        color: theme.colorScheme.primary,
                      ),
                    ),
                  ],
                ),
              ),
              // Transaction list
              Expanded(
                child: transactionsAsync.when(
                  data: (list) {
                    final filtered = list.where((tx) => tx.token.toUpperCase() == token.toUpperCase()).toList();

                    if (filtered.isEmpty) {
                      return Center(
                        child: Column(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            FaIcon(
                              FontAwesomeIcons.receipt,
                              size: 48,
                              color: theme.colorScheme.primary.withAlpha(128),
                            ),
                            const SizedBox(height: 12),
                            Text(
                              'No $token transactions yet',
                              style: theme.textTheme.bodyMedium,
                            ),
                          ],
                        ),
                      );
                    }

                    return ListView.separated(
                      controller: scrollController,
                      itemCount: filtered.length,
                      separatorBuilder: (_, __) => const Divider(height: 1),
                      itemBuilder: (context, index) {
                        final tx = filtered[index];
                        return _TransactionTile(transaction: tx);
                      },
                    );
                  },
                  loading: () => const Center(child: CircularProgressIndicator()),
                  error: (error, _) => Center(
                    child: Text(
                      'Failed to load: $error',
                      style: TextStyle(color: DnaColors.textWarning),
                    ),
                  ),
                ),
              ),
            ],
          ),
        );
      },
    );
  }

  void _showSend(BuildContext context, WidgetRef ref, String currentBalance) {
    Navigator.pop(context); // Close current sheet
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      builder: (context) => _SendSheet(
        walletIndex: walletIndex,
        preselectedToken: token,
        preselectedNetwork: network,
        availableBalance: currentBalance,
      ),
    );
  }

  Color _getTokenColor(String token) {
    switch (token.toUpperCase()) {
      case 'CPUNK':
        return const Color(0xFF00D4AA);
      case 'CELL':
        return const Color(0xFF6B4CE6);
      case 'ETH':
        return const Color(0xFF627EEA);
      case 'SOL':
        return const Color(0xFF9945FF);
      default:
        return DnaColors.textInfo;
    }
  }
}

class _TransactionHistorySheet extends ConsumerWidget {
  final int walletIndex;
  final String? tokenFilter;

  const _TransactionHistorySheet({
    required this.walletIndex,
    this.tokenFilter,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final transactionsAsync = ref.watch(
      transactionsProvider((walletIndex: walletIndex, network: 'Backbone')),
    );
    final theme = Theme.of(context);

    return DraggableScrollableSheet(
      initialChildSize: 0.7,
      minChildSize: 0.5,
      maxChildSize: 0.95,
      expand: false,
      builder: (context, scrollController) {
        return SafeArea(
          child: Column(
            children: [
              // Handle bar
              Container(
                margin: const EdgeInsets.only(top: 8),
                width: 40,
                height: 4,
                decoration: BoxDecoration(
                  color: theme.dividerColor,
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
              // Header
              Padding(
                padding: const EdgeInsets.all(16),
                child: Row(
                  children: [
                    Text(
                      tokenFilter != null ? '$tokenFilter History' : 'Transaction History',
                      style: theme.textTheme.titleLarge,
                    ),
                    const Spacer(),
                    IconButton(
                      icon: const FaIcon(FontAwesomeIcons.arrowsRotate),
                      onPressed: () => ref.invalidate(
                        transactionsProvider((walletIndex: walletIndex, network: 'Backbone')),
                      ),
                      tooltip: 'Refresh',
                    ),
                  ],
                ),
              ),
              const Divider(height: 1),
              // Content
              Expanded(
                child: transactionsAsync.when(
                  data: (list) {
                    // Filter by token if specified
                    final filtered = tokenFilter != null
                        ? list.where((tx) => tx.token.toUpperCase() == tokenFilter!.toUpperCase()).toList()
                        : list;

                    if (filtered.isEmpty) {
                      return Center(
                        child: Column(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            FaIcon(
                              FontAwesomeIcons.receipt,
                              size: 64,
                              color: theme.colorScheme.primary.withAlpha(128),
                            ),
                            const SizedBox(height: 16),
                            Text(
                              tokenFilter != null
                                  ? 'No $tokenFilter transactions yet'
                                  : 'No transactions yet',
                              style: theme.textTheme.titleMedium,
                            ),
                          ],
                        ),
                      );
                    }

                    return ListView.separated(
                      controller: scrollController,
                      itemCount: filtered.length,
                      separatorBuilder: (_, __) => const Divider(height: 1),
                      itemBuilder: (context, index) {
                        final tx = filtered[index];
                        return _TransactionTile(transaction: tx);
                      },
                    );
                  },
                  loading: () => const Center(child: CircularProgressIndicator()),
                  error: (error, _) => Center(
                    child: Padding(
                      padding: const EdgeInsets.all(24),
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          FaIcon(
                            FontAwesomeIcons.circleExclamation,
                            size: 48,
                            color: DnaColors.textWarning,
                          ),
                          const SizedBox(height: 16),
                          Text(
                            'Failed to load transactions',
                            style: theme.textTheme.titleMedium,
                          ),
                          const SizedBox(height: 8),
                          Text(
                            error.toString(),
                            style: theme.textTheme.bodySmall,
                            textAlign: TextAlign.center,
                          ),
                          const SizedBox(height: 16),
                          ElevatedButton(
                            onPressed: () => ref.invalidate(
                              transactionsProvider((walletIndex: walletIndex, network: 'Backbone')),
                            ),
                            child: const Text('Retry'),
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
              ),
            ],
          ),
        );
      },
    );
  }
}

class _TransactionTile extends StatelessWidget {
  final Transaction transaction;

  const _TransactionTile({required this.transaction});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isReceived = transaction.direction.toLowerCase() == 'received';

    return ListTile(
      leading: CircleAvatar(
        backgroundColor: isReceived
            ? const Color(0xFF00D4AA).withAlpha(51)
            : const Color(0xFFFF6B6B).withAlpha(51),
        child: FaIcon(
          isReceived ? FontAwesomeIcons.arrowDown : FontAwesomeIcons.arrowUp,
          color: isReceived ? const Color(0xFF00D4AA) : const Color(0xFFFF6B6B),
        ),
      ),
      title: Text(
        '${transaction.amount} ${transaction.token}',
        style: theme.textTheme.titleMedium?.copyWith(
          fontWeight: FontWeight.bold,
        ),
      ),
      subtitle: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            _formatAddress(transaction.otherAddress),
            style: theme.textTheme.bodySmall?.copyWith(
              fontFamily: 'monospace',
            ),
          ),
          const SizedBox(height: 2),
          Text(
            _formatTimestamp(transaction.timestamp),
            style: theme.textTheme.labelSmall,
          ),
        ],
      ),
      trailing: _StatusChip(status: transaction.status),
      isThreeLine: true,
      onTap: () => _showDetails(context),
    );
  }

  String _formatAddress(String address) {
    if (address.isEmpty) return '-';
    if (address.length <= 20) return address;
    return '${address.substring(0, 10)}...${address.substring(address.length - 8)}';
  }

  String _formatTimestamp(String timestamp) {
    if (timestamp.isEmpty) return '';
    // Try to parse as unix timestamp
    final ts = int.tryParse(timestamp);
    if (ts != null && ts > 0) {
      final date = DateTime.fromMillisecondsSinceEpoch(ts * 1000);
      return '${date.year}-${date.month.toString().padLeft(2, '0')}-${date.day.toString().padLeft(2, '0')} '
             '${date.hour.toString().padLeft(2, '0')}:${date.minute.toString().padLeft(2, '0')}';
    }
    // Return as-is if not a unix timestamp
    return timestamp;
  }

  void _showDetails(BuildContext context) {
    final isReceived = transaction.direction.toLowerCase() == 'received';
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Transaction Details'),
        content: SingleChildScrollView(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              _DetailRow('Hash', transaction.txHash),
              _DetailRow('Status', transaction.status),
              _DetailRow('Direction', isReceived ? 'Received' : 'Sent'),
              _DetailRow('Amount', '${transaction.amount} ${transaction.token}'),
              _DetailRow(isReceived ? 'From' : 'To', transaction.otherAddress),
              _DetailRow('Time', _formatTimestamp(transaction.timestamp)),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () {
              Clipboard.setData(ClipboardData(text: transaction.txHash));
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('Transaction hash copied')),
              );
            },
            child: const Text('Copy Hash'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }
}

class _DetailRow extends StatelessWidget {
  final String label;
  final String value;

  const _DetailRow(this.label, this.value);

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            label,
            style: theme.textTheme.labelSmall?.copyWith(
              color: theme.colorScheme.primary,
            ),
          ),
          const SizedBox(height: 2),
          SelectableText(
            value.isNotEmpty ? value : '-',
            style: theme.textTheme.bodySmall?.copyWith(
              fontFamily: label == 'Hash' || label == 'From' || label == 'To'
                  ? 'monospace'
                  : null,
            ),
          ),
        ],
      ),
    );
  }
}

class _StatusChip extends StatelessWidget {
  final String status;

  const _StatusChip({required this.status});

  @override
  Widget build(BuildContext context) {
    Color color;
    switch (status.toUpperCase()) {
      case 'ACCEPTED':
      case 'CONFIRMED':
        color = const Color(0xFF00D4AA);
        break;
      case 'PENDING':
        color = const Color(0xFFFFAA00);
        break;
      case 'FAILED':
      case 'REJECTED':
        color = const Color(0xFFFF6B6B);
        break;
      default:
        color = DnaColors.textInfo;
    }

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: color.withAlpha(26),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color.withAlpha(77)),
      ),
      child: Text(
        status,
        style: TextStyle(
          color: color,
          fontSize: 11,
          fontWeight: FontWeight.w600,
        ),
      ),
    );
  }
}

/// Gas speed selection chip for Ethereum transactions
class _GasSpeedChip extends StatelessWidget {
  final String label;
  final String sublabel;
  final bool selected;
  final VoidCallback onSelected;

  const _GasSpeedChip({
    required this.label,
    required this.sublabel,
    required this.selected,
    required this.onSelected,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Expanded(
      child: GestureDetector(
        onTap: onSelected,
        child: Container(
          padding: const EdgeInsets.symmetric(vertical: 12),
          decoration: BoxDecoration(
            color: selected
                ? theme.colorScheme.primary.withAlpha(26)
                : theme.colorScheme.surface,
            borderRadius: BorderRadius.circular(8),
            border: Border.all(
              color: selected
                  ? theme.colorScheme.primary
                  : theme.colorScheme.outline.withAlpha(77),
              width: selected ? 2 : 1,
            ),
          ),
          child: Column(
            children: [
              Text(
                label,
                style: TextStyle(
                  fontWeight: selected ? FontWeight.bold : FontWeight.normal,
                  color: selected
                      ? theme.colorScheme.primary
                      : theme.colorScheme.onSurface,
                ),
              ),
              const SizedBox(height: 2),
              Text(
                sublabel,
                style: TextStyle(
                  fontSize: 11,
                  color: selected
                      ? theme.colorScheme.primary.withAlpha(179)
                      : theme.colorScheme.onSurface.withAlpha(128),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
