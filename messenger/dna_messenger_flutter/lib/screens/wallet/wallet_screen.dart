// Wallet Screen - Wallet list and balances
import 'dart:convert' show base64Decode;
import 'dart:typed_data' show Uint8List;
import 'dart:ui';
import 'package:fl_chart/fl_chart.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_svg/flutter_svg.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import 'package:qr_flutter/qr_flutter.dart';
import '../../ffi/dna_engine.dart' show Contact, Transaction, UserProfile, Wallet;
import '../../providers/addressbook_provider.dart';
import '../../providers/identity_profile_cache_provider.dart';
import '../../providers/profile_provider.dart' show fullProfileProvider;
import '../../providers/portfolio_history_provider.dart';
import '../../providers/providers.dart' hide UserProfile;
import '../../design_system/design_system.dart'; // includes DnaColors, DnaGradients, DnaSpacing
import '../../providers/price_provider.dart';
import 'address_book_screen.dart';
import 'address_dialog.dart';
import '../../l10n/app_localizations.dart';

/// Network filter for the wallet assets list (null = show all)
final walletNetworkFilterProvider = StateProvider<String?>((ref) => null);

/// Render a crypto icon asset, supporting both SVG and PNG formats.
Widget buildCryptoIcon(String assetPath, {BoxFit fit = BoxFit.contain}) {
  if (assetPath.endsWith('.svg')) {
    return SvgPicture.asset(assetPath, fit: fit);
  }
  return Image.asset(assetPath, fit: fit);
}

/// Get the icon path for a token
String? getTokenIconPath(String token) {
  switch (token.toUpperCase()) {
    case 'ETH':
      return 'assets/icons/crypto/eth.svg';
    case 'SOL':
      return 'assets/icons/crypto/sol.svg';
    case 'TRX':
      return 'assets/icons/crypto/trx.svg';
    case 'BNB':
      return 'assets/icons/crypto/bnb.svg';
    case 'USDT':
      return 'assets/icons/crypto/usdt.svg';
    case 'KEL':
      return 'assets/icons/crypto/kel.svg';
    case 'NYS':
      return 'assets/icons/crypto/nys.png';
    case 'CPUNK':
      return 'assets/icons/crypto/cpunk.png';
    case 'CELL':
    case 'QEVM':
      return 'assets/icons/crypto/cell.svg';  // CF20 tokens use Cellframe icon
    default:
      return null;
  }
}

/// sigType-to-network mapping for wallet address lookup
/// Cellframe=4, ETH=100, SOL=101, TRX=102, BSC=103
String? getWalletAddressByNetwork(List<Wallet> wallets, String network) {
  final int targetSigType;
  switch (network.toLowerCase()) {
    case 'ethereum':
      targetSigType = 100;
      break;
    case 'solana':
      targetSigType = 101;
      break;
    case 'tron':
      targetSigType = 102;
      break;
    case 'bsc':
      targetSigType = 103;
      break;
    default: // cellframe
      targetSigType = 4;
      break;
  }
  for (final w in wallets) {
    if (w.sigType == targetSigType) return w.address;
  }
  // Fallback to first wallet if no match
  return wallets.isNotEmpty ? wallets.first.address : null;
}

/// Convert internal network name to display label
String getNetworkDisplayLabel(String network) {
  switch (network.toLowerCase()) {
    case 'cellframe':
      return 'CF20';
    case 'ethereum':
      return 'ERC20';
    case 'solana':
      return 'SPL';
    case 'tron':
      return 'TRC20';
    case 'bsc':
      return 'BEP20';
    default:
      return network;
  }
}

/// Format a USD value for display with comma separators
String _formatUsdValue(double value) {
  if (value >= 1000) {
    // Add comma separators for thousands
    final parts = value.toStringAsFixed(2).split('.');
    final intPart = parts[0];
    final buffer = StringBuffer();
    for (var i = 0; i < intPart.length; i++) {
      if (i > 0 && (intPart.length - i) % 3 == 0) buffer.write(',');
      buffer.write(intPart[i]);
    }
    return '${buffer.toString()}.${parts[1]}';
  } else if (value >= 1) {
    return value.toStringAsFixed(2);
  } else if (value >= 0.01) {
    return value.toStringAsFixed(4);
  } else {
    return value.toStringAsFixed(6);
  }
}

/// Truncate a balance string to at most 8 decimal places
String _truncateBalance(String balance) {
  final dotIndex = balance.indexOf('.');
  if (dotIndex < 0) return balance;
  final decimals = balance.length - dotIndex - 1;
  if (decimals <= 8) return balance;
  return balance.substring(0, dotIndex + 9);
}

class WalletScreen extends ConsumerStatefulWidget {
  const WalletScreen({super.key});

  @override
  ConsumerState<WalletScreen> createState() => _WalletScreenState();
}

class _WalletScreenState extends ConsumerState<WalletScreen> {
  @override
  void initState() {
    super.initState();
    // Trigger silent background refresh when wallet screen opens
    // This runs after the first build, so cached data is shown first
    Future.microtask(() {
      if (mounted) {
        ref.read(allBalancesProvider.notifier).refresh();
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    final wallets = ref.watch(walletsProvider);
    final selectedIndex = ref.watch(selectedWalletIndexProvider);

    return Scaffold(
      appBar: AppBar(
        title: Text(AppLocalizations.of(context).walletTitle),
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
            onPressed: () {
              ref.read(walletsProvider.notifier).refresh();
              ref.read(allBalancesProvider.notifier).refresh(force: true);
            },
            tooltip: 'Refresh',
          ),
        ],
      ),
      body: wallets.when(
        data: (list) => _buildContent(context, list, selectedIndex),
        loading: () {
          // Show cached data if available, spinner only on first load
          final cached = wallets.valueOrNull;
          if (cached != null && cached.isNotEmpty) {
            return _buildContent(context, cached, selectedIndex);
          }
          return const Center(child: CircularProgressIndicator());
        },
        error: (error, stack) => _buildError(context, error),
      ),
    );
  }

  Widget _buildContent(
    BuildContext context,
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
        await ref.read(allBalancesProvider.notifier).refresh(force: true);
      },
      child: ListView(
        children: [
          const _WalletHeroCard(),
          const _ActionButtonsRow(),
          const _ChainFilterBar(),
          const SizedBox(height: 4),
          const _AllBalancesSection(),
        ],
      ),
    );
  }

  Widget _buildError(BuildContext context, Object error) {
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

class _ActionButtonsRow extends ConsumerWidget {
  const _ActionButtonsRow();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final walletsAsync = ref.watch(walletsProvider);

    return Padding(
      padding: const EdgeInsets.only(bottom: 24),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          _PillAction(
            icon: FontAwesomeIcons.arrowUp,
            label: AppLocalizations.of(context).walletSend,
            onTap: () {
              showModalBottomSheet(
                context: context,
                isScrollControlled: true,
                builder: (context) => const _SendSheet(walletIndex: 0),
              );
            },
          ),
          const SizedBox(width: 16),
          _PillAction(
            icon: FontAwesomeIcons.arrowDown,
            label: AppLocalizations.of(context).walletReceive,
            onTap: () {
              final wallets = walletsAsync.valueOrNull ?? [];
              showModalBottomSheet(
                context: context,
                builder: (context) => _ReceiveSheet(wallets: wallets),
              );
            },
          ),
        ],
      ),
    );
  }
}

class _PillAction extends StatelessWidget {
  final IconData icon;
  final String label;
  final VoidCallback onTap;

  const _PillAction({
    required this.icon,
    required this.label,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        width: 110,
        padding: const EdgeInsets.symmetric(vertical: 12),
        decoration: BoxDecoration(
          gradient: DnaGradients.primary,
          borderRadius: BorderRadius.circular(DnaSpacing.radiusFull),
          boxShadow: [
            BoxShadow(
              color: DnaColors.gradientStart.withValues(alpha: 0.25),
              blurRadius: 10,
              offset: const Offset(0, 4),
            ),
          ],
        ),
        child: Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Container(
              width: 26,
              height: 26,
              decoration: BoxDecoration(
                color: Colors.white.withValues(alpha: 0.2),
                shape: BoxShape.circle,
              ),
              child: Center(
                child: FaIcon(icon, color: Colors.white, size: 12),
              ),
            ),
            const SizedBox(width: 8),
            Text(
              label,
              style: const TextStyle(
                color: Colors.white,
                fontSize: 14,
                fontWeight: FontWeight.w600,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

/// Receive sheet with network selector and real QR code
class _ReceiveSheet extends StatefulWidget {
  final List<Wallet> wallets;

  const _ReceiveSheet({required this.wallets});

  @override
  State<_ReceiveSheet> createState() => _ReceiveSheetState();
}

class _ReceiveSheetState extends State<_ReceiveSheet> {
  String _selectedNetwork = 'cellframe'; // Default to CF20

  static const _networks = [
    ('cellframe', 'CF20', 'assets/icons/crypto/cell.svg'),
    ('ethereum', 'ERC20', 'assets/icons/crypto/eth.svg'),
    ('solana', 'SPL', 'assets/icons/crypto/sol.svg'),
    ('tron', 'TRC20', 'assets/icons/crypto/trx.svg'),
    ('bsc', 'BEP20', 'assets/icons/crypto/bnb.svg'),
  ];

  String get _currentAddress =>
      getWalletAddressByNetwork(widget.wallets, _selectedNetwork) ?? '';

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final address = _currentAddress;

    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(AppLocalizations.of(context).walletReceive, style: theme.textTheme.titleLarge),
            const SizedBox(height: 16),
            // Network selector
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: _networks.map((entry) {
                final (network, label, icon) = entry;
                final isSelected = _selectedNetwork == network;
                return Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 6),
                  child: GestureDetector(
                    onTap: () => setState(() => _selectedNetwork = network),
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Container(
                          width: 44,
                          height: 44,
                          decoration: BoxDecoration(
                            color: isSelected
                                ? theme.colorScheme.primary.withAlpha(26)
                                : theme.colorScheme.surface,
                            shape: BoxShape.circle,
                            border: Border.all(
                              color: isSelected
                                  ? theme.colorScheme.primary
                                  : theme.colorScheme.outline.withAlpha(77),
                              width: isSelected ? 2 : 1,
                            ),
                          ),
                          child: Padding(
                            padding: const EdgeInsets.all(8),
                            child: buildCryptoIcon(icon),
                          ),
                        ),
                        const SizedBox(height: 4),
                        Text(
                          label,
                          style: TextStyle(
                            fontSize: 11,
                            fontWeight: isSelected ? FontWeight.bold : FontWeight.normal,
                            color: isSelected
                                ? theme.colorScheme.primary
                                : theme.colorScheme.onSurface.withAlpha(179),
                          ),
                        ),
                      ],
                    ),
                  ),
                );
              }).toList(),
            ),
            const SizedBox(height: 16),
            // QR code + address (scrollable if needed)
            Flexible(
              child: SingleChildScrollView(
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Container(
                      padding: const EdgeInsets.all(16),
                      decoration: BoxDecoration(
                        color: Colors.white,
                        borderRadius: BorderRadius.circular(12),
                      ),
                      child: address.isNotEmpty
                          ? QrImageView(
                              data: address,
                              version: QrVersions.auto,
                              size: 180,
                              backgroundColor: Colors.white,
                            )
                          : const SizedBox(
                              width: 180,
                              height: 180,
                              child: Center(child: Text('No address')),
                            ),
                    ),
                    const SizedBox(height: 16),
                    // Address text
                    Text(
                      address,
                      style: theme.textTheme.bodySmall?.copyWith(fontFamily: 'monospace'),
                      textAlign: TextAlign.center,
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 16),
            // Copy button pinned at bottom
            DnaButton(
              label: AppLocalizations.of(context).walletCopyAddress,
              icon: FontAwesomeIcons.copy,
              expand: true,
              onPressed: address.isNotEmpty
                  ? () {
                      Clipboard.setData(ClipboardData(text: address));
                      final messenger = ScaffoldMessenger.of(context);
                      Navigator.pop(context);
                      messenger.showSnackBar(
                        SnackBar(
                          content: Row(
                            children: [
                              FaIcon(FontAwesomeIcons.circleCheck,
                                  size: 18, color: Colors.white),
                              const SizedBox(width: 10),
                              Text(AppLocalizations.of(context).walletAddressCopied,
                                  style: const TextStyle(fontSize: 15)),
                            ],
                          ),
                          duration: const Duration(seconds: 2),
                          behavior: SnackBarBehavior.floating,
                          margin: const EdgeInsets.all(16),
                          shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(10)),
                        ),
                      );
                    }
                  : null,
            ),
          ],
        ),
      ),
    );
  }
}

class _WalletHeroCard extends ConsumerWidget {
  const _WalletHeroCard();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final fingerprint = ref.watch(currentFingerprintProvider);
    final nameCache = ref.watch(nameResolverProvider);
    final identityName = fingerprint != null ? nameCache[fingerprint] : null;
    final l10n = AppLocalizations.of(context);

    // Trigger resolution if not yet cached
    if (fingerprint != null && !nameCache.containsKey(fingerprint)) {
      ref.read(nameResolverProvider.notifier).resolveName(fingerprint);
    }

    // Get avatar from own profile (engine.getProfile returns avatar directly)
    Widget avatarWidget = DnaAvatar(
      name: identityName ?? 'W',
      size: DnaAvatarSize.lg,
    );
    final ownProfile = ref.watch(fullProfileProvider).valueOrNull;
    if (ownProfile != null && ownProfile.avatarBase64.isNotEmpty) {
      try {
        final bytes = _base64ToBytes(ownProfile.avatarBase64);
        if (bytes.isNotEmpty) {
          avatarWidget = DnaAvatar(
            imageBytes: bytes,
            name: identityName,
            size: DnaAvatarSize.lg,
          );
        }
      } catch (_) {}
    }

    return GestureDetector(
      onTap: () => _showPortfolioBreakdown(context, ref),
      child: Container(
      margin: const EdgeInsets.fromLTRB(DnaSpacing.lg, DnaSpacing.lg, DnaSpacing.lg, DnaSpacing.sm),
      clipBehavior: Clip.antiAlias,
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(DnaSpacing.radiusXl),
      ),
      child: Stack(
        children: [
          // Gradient background
          Positioned.fill(
            child: Container(
              decoration: const BoxDecoration(
                gradient: DnaGradients.primaryVertical,
              ),
            ),
          ),
          // Decorative circles for depth
          Positioned(
            top: -30,
            right: -20,
            child: Container(
              width: 120,
              height: 120,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: Colors.white.withValues(alpha: 0.06),
              ),
            ),
          ),
          Positioned(
            bottom: -40,
            left: -30,
            child: Container(
              width: 140,
              height: 140,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: Colors.white.withValues(alpha: 0.04),
              ),
            ),
          ),
          // Glassmorphism overlay
          Positioned.fill(
            child: BackdropFilter(
              filter: ImageFilter.blur(sigmaX: 1.5, sigmaY: 1.5),
              child: Container(
                decoration: BoxDecoration(
                  color: Colors.white.withValues(alpha: 0.05),
                  borderRadius: BorderRadius.circular(DnaSpacing.radiusXl),
                  border: Border.all(
                    color: Colors.white.withValues(alpha: 0.15),
                    width: 1,
                  ),
                ),
              ),
            ),
          ),
          // Content
          Padding(
            padding: const EdgeInsets.all(20),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // Avatar + name row
                Row(
                  children: [
                    avatarWidget,
                    const SizedBox(width: 14),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            children: [
                              Text(
                                l10n.walletMyWallet,
                                style: TextStyle(
                                  color: Colors.white.withValues(alpha: 0.7),
                                  fontSize: 12,
                                ),
                              ),
                              Builder(builder: (context) {
                                final hideBalances = ref.watch(walletSettingsProvider).hideBalances;
                                final change24h = ref.watch(portfolioChange24hProvider);
                                if (!hideBalances && change24h != null && change24h != 0.0) {
                                  return Padding(
                                    padding: const EdgeInsets.only(left: 8),
                                    child: _Change24hBadge(changePercent: change24h, light: true),
                                  );
                                }
                                return const SizedBox.shrink();
                              }),
                            ],
                          ),
                          const SizedBox(height: 2),
                          Text(
                            identityName ?? 'Wallet',
                            style: const TextStyle(
                              color: Colors.white,
                              fontSize: 22,
                              fontWeight: FontWeight.bold,
                            ),
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                          ),
                        ],
                      ),
                    ),
                    GestureDetector(
                      onTap: () => ref.read(walletSettingsProvider.notifier).toggleHideBalances(),
                      child: Container(
                        padding: const EdgeInsets.all(8),
                        decoration: BoxDecoration(
                          color: Colors.white.withValues(alpha: 0.1),
                          shape: BoxShape.circle,
                        ),
                        child: FaIcon(
                          ref.watch(walletSettingsProvider).hideBalances
                              ? FontAwesomeIcons.eyeSlash
                              : FontAwesomeIcons.eye,
                          size: 15,
                          color: Colors.white.withValues(alpha: 0.7),
                        ),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 16),
                // Portfolio total + 24h change
                Builder(builder: (context) {
                  final cachedTotal = ref.watch(cachedPortfolioTotalProvider);
                  final totalValue = cachedTotal.valueOrNull;
                  final hideBalances = ref.watch(walletSettingsProvider).hideBalances;
                  return Text(
                    hideBalances
                        ? '\$*****'
                        : (totalValue != null && totalValue > 0)
                            ? '\$${_formatUsdValue(totalValue)}'
                            : '\$0.00',
                    style: const TextStyle(
                      color: Colors.white,
                      fontSize: 30,
                      fontWeight: FontWeight.w700,
                      letterSpacing: -0.5,
                    ),
                  );
                }),
                // Portfolio sparkline
                const _PortfolioSparkline(),
              ],
            ),
          ),
        ],
      ),
      ),
    );
  }

  void _showPortfolioBreakdown(BuildContext context, WidgetRef ref) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (context) => const _PortfolioBreakdownSheet(),
    );
  }
}

/// Portfolio breakdown bottom sheet — token allocation donut + chain breakdown
class _PortfolioBreakdownSheet extends ConsumerWidget {
  const _PortfolioBreakdownSheet();

  // Official brand colors — maximum contrast, globally recognizable
  static const _tokenColors = <String, Color>{
    'CPUNK': Color(0xFF00E5A0),  // CPUNK vibrant cyan-green (brand)
    'CELL': Color(0xFF7B3FE4),   // Cellframe purple (official)
    'ETH': Color(0xFF627EEA),    // Ethereum blue (official)
    'SOL': Color(0xFF14F195),    // Solana green (official brand)
    'TRX': Color(0xFFEF0027),    // TRON red (official)
    'USDT': Color(0xFF50AF95),   // Tether green (official)
    'USDC': Color(0xFF2775CA),   // USD Coin blue (official)
    'KEL': Color(0xFFFF8C42),    // KEL warm orange
    'NYS': Color(0xFFE040FB),    // NYS magenta/purple
    'QEVM': Color(0xFF4FC3F7),   // QEVM light blue
    'BNB': Color(0xFFF0B90B),    // BNB yellow (official brand)
  };

  // Chain brand colors — distinct from each other
  static const _chainColors = <String, Color>{
    'cellframe': Color(0xFF7B3FE4),  // Cellframe purple
    'ethereum': Color(0xFF627EEA),   // Ethereum blue
    'solana': Color(0xFF14F195),     // Solana green
    'tron': Color(0xFFEF0027),       // TRON red
    'bsc': Color(0xFFF0B90B),        // BNB yellow
  };

  static const _chainIcons = <String, String>{
    'cellframe': 'assets/icons/crypto/cell.svg',
    'ethereum': 'assets/icons/crypto/eth.svg',
    'solana': 'assets/icons/crypto/sol.svg',
    'tron': 'assets/icons/crypto/trx.svg',
    'bsc': 'assets/icons/crypto/bnb.svg',
  };

  Color _colorForToken(String token) =>
      _tokenColors[token.toUpperCase()] ?? DnaColors.textInfo;

  Color _colorForChain(String chain) =>
      _chainColors[chain.toLowerCase()] ?? DnaColors.textInfo;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final allBalances = ref.watch(allBalancesProvider).valueOrNull ?? [];
    final prices = ref.watch(priceProvider).valueOrNull ?? {};
    final cachedTotal = ref.watch(cachedPortfolioTotalProvider).valueOrNull ?? 0.0;

    // Build token + chain breakdowns
    final tokenUsd = <String, double>{};
    final chainUsd = <String, double>{};

    for (final wb in allBalances) {
      final token = wb.balance.token.toUpperCase();
      final bal = double.tryParse(wb.balance.balance) ?? 0.0;
      final price = prices[token]?.price ?? 0.0;
      final usd = bal * price;
      if (usd <= 0) continue;

      tokenUsd[token] = (tokenUsd[token] ?? 0.0) + usd;
      final chain = wb.balance.network.toLowerCase();
      chainUsd[chain] = (chainUsd[chain] ?? 0.0) + usd;
    }

    final sortedTokens = tokenUsd.entries.toList()
      ..sort((a, b) => b.value.compareTo(a.value));
    final sortedChains = chainUsd.entries.toList()
      ..sort((a, b) => b.value.compareTo(a.value));

    final total = cachedTotal > 0 ? cachedTotal : tokenUsd.values.fold(0.0, (a, b) => a + b);

    return Container(
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        borderRadius: const BorderRadius.vertical(top: Radius.circular(DnaSpacing.radiusXl)),
      ),
      child: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.fromLTRB(DnaSpacing.lg, DnaSpacing.sm, DnaSpacing.lg, DnaSpacing.lg),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              // Handle bar
              Container(
                width: 40, height: 4,
                margin: const EdgeInsets.only(bottom: DnaSpacing.lg),
                decoration: BoxDecoration(
                  color: theme.dividerColor,
                  borderRadius: BorderRadius.circular(2),
                ),
              ),

              // Gradient header card
              Container(
                width: double.infinity,
                padding: const EdgeInsets.symmetric(vertical: 24, horizontal: 20),
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
                  children: [
                    Text(
                      'Portfolio',
                      style: TextStyle(
                        color: Colors.white.withValues(alpha: 0.7),
                        fontSize: 14,
                        fontWeight: FontWeight.w500,
                      ),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      '\$${_formatUsdValue(total)}',
                      style: const TextStyle(
                        color: Colors.white,
                        fontSize: 36,
                        fontWeight: FontWeight.w800,
                        letterSpacing: -1,
                      ),
                    ),
                    const SizedBox(height: 4),
                    Builder(builder: (context) {
                      final change24h = ref.watch(portfolioChange24hProvider);
                      if (change24h != null && change24h != 0.0) {
                        return _Change24hBadge(changePercent: change24h, light: true);
                      }
                      return const SizedBox.shrink();
                    }),
                  ],
                ),
              ),

              const SizedBox(height: 24),

              // ── Token Allocation ──
              _SectionHeader(title: 'Token Allocation'),
              const SizedBox(height: 16),

              if (sortedTokens.isNotEmpty) ...[
                // Donut chart with total in center
                SizedBox(
                  height: 220,
                  child: Stack(
                    alignment: Alignment.center,
                    children: [
                      // Subtle glow behind chart
                      Container(
                        width: 180, height: 180,
                        decoration: BoxDecoration(
                          shape: BoxShape.circle,
                          boxShadow: [
                            BoxShadow(
                              color: DnaColors.gradientStart.withValues(alpha: 0.08),
                              blurRadius: 40,
                              spreadRadius: 10,
                            ),
                          ],
                        ),
                      ),
                      PieChart(
                        PieChartData(
                          sectionsSpace: 2,
                          centerSpaceRadius: 55,
                          startDegreeOffset: -90,
                          sections: sortedTokens.asMap().entries.map((entry) {
                            final e = entry.value;
                            final pct = total > 0 ? (e.value / total * 100) : 0.0;
                            final color = _colorForToken(e.key);
                            return PieChartSectionData(
                              value: e.value,
                              gradient: SweepGradient(
                                colors: [color, color.withValues(alpha: 0.7)],
                              ),
                              radius: 36,
                              title: '',
                              badgeWidget: pct >= 8 ? _PieBadge(
                                token: e.key,
                                color: color,
                              ) : null,
                              badgePositionPercentageOffset: 1.6,
                            );
                          }).toList(),
                        ),
                        duration: const Duration(milliseconds: 800),
                        curve: Curves.easeOutCubic,
                      ),
                      // Center content
                      Column(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Text(
                            '${sortedTokens.length}',
                            style: theme.textTheme.headlineSmall?.copyWith(
                              fontWeight: FontWeight.w800,
                              color: theme.colorScheme.primary,
                            ),
                          ),
                          Text(
                            'tokens',
                            style: theme.textTheme.bodySmall?.copyWith(
                              color: theme.colorScheme.onSurface.withValues(alpha: 0.4),
                              fontSize: 11,
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 16),

                // Token legend cards
                ...sortedTokens.map((e) {
                  final pct = total > 0 ? (e.value / total * 100) : 0.0;
                  final color = _colorForToken(e.key);
                  final iconPath = getTokenIconPath(e.key);
                  return Container(
                    margin: const EdgeInsets.only(bottom: 8),
                    padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
                    decoration: BoxDecoration(
                      color: color.withValues(alpha: 0.06),
                      borderRadius: BorderRadius.circular(DnaSpacing.radiusMd),
                      border: Border.all(color: color.withValues(alpha: 0.15)),
                    ),
                    child: Row(
                      children: [
                        // Token icon
                        Container(
                          width: 34, height: 34,
                          decoration: BoxDecoration(
                            color: color.withValues(alpha: 0.12),
                            shape: BoxShape.circle,
                          ),
                          child: iconPath != null
                              ? Padding(
                                  padding: const EdgeInsets.all(6),
                                  child: buildCryptoIcon(iconPath),
                                )
                              : Center(
                                  child: Text(e.key[0], style: TextStyle(
                                    color: color, fontWeight: FontWeight.bold, fontSize: 14)),
                                ),
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(e.key, style: theme.textTheme.titleSmall?.copyWith(
                                fontWeight: FontWeight.w700)),
                              const SizedBox(height: 2),
                              // Mini progress bar
                              ClipRRect(
                                borderRadius: BorderRadius.circular(3),
                                child: SizedBox(
                                  height: 4,
                                  child: LinearProgressIndicator(
                                    value: pct / 100,
                                    backgroundColor: color.withValues(alpha: 0.1),
                                    valueColor: AlwaysStoppedAnimation(color),
                                  ),
                                ),
                              ),
                            ],
                          ),
                        ),
                        const SizedBox(width: 12),
                        Column(
                          crossAxisAlignment: CrossAxisAlignment.end,
                          children: [
                            Text('\$${_formatUsdValue(e.value)}',
                              style: theme.textTheme.titleSmall?.copyWith(
                                fontWeight: FontWeight.w700)),
                            Text('${pct.toStringAsFixed(1)}%',
                              style: theme.textTheme.bodySmall?.copyWith(
                                color: color, fontWeight: FontWeight.w600)),
                          ],
                        ),
                      ],
                    ),
                  );
                }),
              ],

              const SizedBox(height: 24),

              // ── Chain Distribution ──
              _SectionHeader(title: 'Chain Distribution'),
              const SizedBox(height: 16),

              if (sortedChains.isNotEmpty) ...[
                ...sortedChains.map((e) {
                  final pct = total > 0 ? (e.value / total * 100) : 0.0;
                  final color = _colorForChain(e.key);
                  final label = getNetworkDisplayLabel(e.key);
                  final iconPath = _chainIcons[e.key.toLowerCase()];
                  return Container(
                    margin: const EdgeInsets.only(bottom: 10),
                    padding: const EdgeInsets.all(16),
                    decoration: BoxDecoration(
                      color: theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.4),
                      borderRadius: BorderRadius.circular(DnaSpacing.radiusMd),
                      border: Border.all(
                        color: color.withValues(alpha: 0.2),
                      ),
                    ),
                    child: Column(
                      children: [
                        Row(
                          children: [
                            // Chain icon
                            Container(
                              width: 38, height: 38,
                              padding: const EdgeInsets.all(7),
                              decoration: BoxDecoration(
                                gradient: LinearGradient(
                                  begin: Alignment.topLeft,
                                  end: Alignment.bottomRight,
                                  colors: [
                                    color.withValues(alpha: 0.15),
                                    color.withValues(alpha: 0.05),
                                  ],
                                ),
                                borderRadius: BorderRadius.circular(10),
                                border: Border.all(color: color.withValues(alpha: 0.2)),
                              ),
                              child: iconPath != null
                                  ? buildCryptoIcon(iconPath)
                                  : Center(child: Text(label[0],
                                      style: TextStyle(color: color, fontWeight: FontWeight.bold))),
                            ),
                            const SizedBox(width: 14),
                            Expanded(
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Text(label, style: theme.textTheme.titleSmall?.copyWith(
                                    fontWeight: FontWeight.w700, fontSize: 15)),
                                  Text(e.key.substring(0, 1).toUpperCase() + e.key.substring(1),
                                    style: theme.textTheme.bodySmall?.copyWith(
                                      color: theme.colorScheme.onSurface.withValues(alpha: 0.4),
                                      fontSize: 11)),
                                ],
                              ),
                            ),
                            Column(
                              crossAxisAlignment: CrossAxisAlignment.end,
                              children: [
                                Text('\$${_formatUsdValue(e.value)}',
                                  style: theme.textTheme.titleMedium?.copyWith(
                                    fontWeight: FontWeight.w800)),
                                Container(
                                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                                  decoration: BoxDecoration(
                                    color: color.withValues(alpha: 0.12),
                                    borderRadius: BorderRadius.circular(DnaSpacing.radiusFull),
                                  ),
                                  child: Text('${pct.toStringAsFixed(1)}%',
                                    style: TextStyle(
                                      color: color,
                                      fontSize: 12,
                                      fontWeight: FontWeight.w700,
                                    )),
                                ),
                              ],
                            ),
                          ],
                        ),
                        const SizedBox(height: 12),
                        // Gradient progress bar
                        ClipRRect(
                          borderRadius: BorderRadius.circular(5),
                          child: Container(
                            height: 8,
                            decoration: BoxDecoration(
                              color: theme.colorScheme.surfaceContainerHighest,
                              borderRadius: BorderRadius.circular(5),
                            ),
                            child: FractionallySizedBox(
                              alignment: Alignment.centerLeft,
                              widthFactor: pct / 100,
                              child: Container(
                                decoration: BoxDecoration(
                                  gradient: LinearGradient(
                                    colors: [
                                      color,
                                      color.withValues(alpha: 0.6),
                                    ],
                                  ),
                                  borderRadius: BorderRadius.circular(5),
                                  boxShadow: [
                                    BoxShadow(
                                      color: color.withValues(alpha: 0.4),
                                      blurRadius: 6,
                                      offset: const Offset(0, 2),
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
                }),
              ],

              const SizedBox(height: DnaSpacing.lg),
              SizedBox(
                width: double.infinity,
                child: TextButton(
                  onPressed: () => Navigator.pop(context),
                  child: const Text('Close'),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

/// Section header with gradient accent line
class _SectionHeader extends StatelessWidget {
  final String title;
  const _SectionHeader({required this.title});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Row(
      children: [
        Container(
          width: 3, height: 18,
          decoration: BoxDecoration(
            gradient: DnaGradients.primary,
            borderRadius: BorderRadius.circular(2),
          ),
        ),
        const SizedBox(width: 10),
        Text(title, style: theme.textTheme.titleMedium?.copyWith(
          fontWeight: FontWeight.w700,
          letterSpacing: -0.3,
        )),
      ],
    );
  }
}

/// Pie chart badge — token icon floating outside the donut ring
class _PieBadge extends StatelessWidget {
  final String token;
  final Color color;
  const _PieBadge({required this.token, required this.color});

  @override
  Widget build(BuildContext context) {
    final iconPath = getTokenIconPath(token);
    return Container(
      width: 32, height: 32,
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        shape: BoxShape.circle,
        border: Border.all(color: color, width: 2.5),
        boxShadow: [
          BoxShadow(
            color: color.withValues(alpha: 0.4),
            blurRadius: 8,
            spreadRadius: 2,
          ),
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.15),
            blurRadius: 4,
            offset: const Offset(0, 2),
          ),
        ],
      ),
      child: iconPath != null
          ? Padding(
              padding: const EdgeInsets.all(5),
              child: buildCryptoIcon(iconPath),
            )
          : Center(
              child: Text(token[0], style: TextStyle(
                color: color, fontWeight: FontWeight.w900, fontSize: 12)),
            ),
    );
  }
}

/// Decode base64 avatar string to bytes
Uint8List _base64ToBytes(String base64Str) {
  try {
    // Strip data URI prefix if present
    final raw = base64Str.contains(',') ? base64Str.split(',').last : base64Str;
    return Uint8List.fromList(
      List<int>.from(Uri.parse('data:;base64,$raw').data!.contentAsBytes()),
    );
  } catch (_) {
    try {
      return Uint8List.fromList(
        List<int>.from(base64Decode(base64Str)),
      );
    } catch (_) {
      return Uint8List(0);
    }
  }
}

/// Portfolio sparkline widget — shows 7-day trend inside hero card
class _PortfolioSparkline extends ConsumerWidget {
  const _PortfolioSparkline();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final history = ref.watch(portfolioHistoryProvider);
    final hideBalances = ref.watch(walletSettingsProvider).hideBalances;

    // Need at least 2 points for a line
    if (history.length < 2 || hideBalances) {
      return const SizedBox(height: 8);
    }

    final spots = <FlSpot>[];
    for (int i = 0; i < history.length; i++) {
      spots.add(FlSpot(i.toDouble(), history[i].totalUsd));
    }

    // Determine trend color
    final isUp = history.last.totalUsd >= history.first.totalUsd;
    final lineColor = isUp
        ? const Color(0xFF34D399) // green
        : const Color(0xFFEF4444); // red

    return Padding(
      padding: const EdgeInsets.only(top: 12),
      child: SizedBox(
        height: 50,
        child: LineChart(
          LineChartData(
            gridData: const FlGridData(show: false),
            titlesData: const FlTitlesData(show: false),
            borderData: FlBorderData(show: false),
            lineTouchData: const LineTouchData(enabled: false),
            clipData: const FlClipData.all(),
            lineBarsData: [
              LineChartBarData(
                spots: spots,
                isCurved: true,
                curveSmoothness: 0.3,
                color: lineColor,
                barWidth: 2,
                isStrokeCapRound: true,
                dotData: const FlDotData(show: false),
                belowBarData: BarAreaData(
                  show: true,
                  gradient: LinearGradient(
                    begin: Alignment.topCenter,
                    end: Alignment.bottomCenter,
                    colors: [
                      lineColor.withValues(alpha: 0.25),
                      lineColor.withValues(alpha: 0.0),
                    ],
                  ),
                ),
              ),
            ],
          ),
          duration: const Duration(milliseconds: 300),
        ),
      ),
    );
  }
}

/// Chain filter chip bar — horizontal scrollable chips below hero card
class _ChainFilterBar extends ConsumerWidget {
  const _ChainFilterBar();

  static const _chains = [
    ('bsc', 'BNB', 'assets/icons/crypto/bnb.svg'),
    ('cellframe', 'CELL', 'assets/icons/crypto/cell.svg'),
    ('ethereum', 'ETH', 'assets/icons/crypto/eth.svg'),
    ('solana', 'SOL', 'assets/icons/crypto/sol.svg'),
    ('tron', 'TRX', 'assets/icons/crypto/trx.svg'),
  ];

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final activeFilter = ref.watch(walletNetworkFilterProvider);
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: DnaSpacing.lg, vertical: DnaSpacing.xs),
      child: SingleChildScrollView(
        scrollDirection: Axis.horizontal,
        child: Row(
          children: _chains.map((entry) {
            final (network, label, iconPath) = entry;
            final isSelected = activeFilter == network;

            return Padding(
              padding: const EdgeInsets.only(right: 8),
              child: GestureDetector(
                onTap: () {
                  ref.read(walletNetworkFilterProvider.notifier).state =
                      isSelected ? null : network;
                },
                child: AnimatedContainer(
                  duration: const Duration(milliseconds: 200),
                  padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
                  decoration: BoxDecoration(
                    color: isSelected
                        ? theme.colorScheme.primary.withValues(alpha: 0.15)
                        : theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.5),
                    borderRadius: BorderRadius.circular(DnaSpacing.radiusFull),
                    border: Border.all(
                      color: isSelected
                          ? theme.colorScheme.primary.withValues(alpha: 0.5)
                          : theme.colorScheme.outline.withValues(alpha: 0.1),
                      width: 1,
                    ),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      if (iconPath != null) ...[
                        SizedBox(
                          width: 18,
                          height: 18,
                          child: buildCryptoIcon(iconPath),
                        ),
                        const SizedBox(width: 6),
                      ],
                      Text(
                        label,
                        style: TextStyle(
                          fontSize: 13,
                          fontWeight: isSelected ? FontWeight.w600 : FontWeight.normal,
                          color: isSelected
                              ? theme.colorScheme.primary
                              : theme.colorScheme.onSurface.withValues(alpha: 0.7),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            );
          }).toList(),
        ),
      ),
    );
  }
}

class _AllBalancesSection extends ConsumerWidget {
  const _AllBalancesSection();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final allBalances = ref.watch(allBalancesProvider);
    final grouped = ref.watch(groupedBalancesProvider);
    final walletSettings = ref.watch(walletSettingsProvider);
    final networkFilter = ref.watch(walletNetworkFilterProvider);
    final theme = Theme.of(context);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        allBalances.when(
          data: (_) => _buildGroupedList(grouped, networkFilter, walletSettings, theme),
          loading: () {
            if (grouped.isNotEmpty) {
              return _buildGroupedList(grouped, networkFilter, walletSettings, theme);
            }
            return const Padding(
              padding: EdgeInsets.all(16),
              child: Center(child: CircularProgressIndicator()),
            );
          },
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

  Widget _buildGroupedList(List<GroupedToken> groups, String? networkFilter,
      WalletSettingsState walletSettings, ThemeData theme) {
    var filteredGroups = groups.toList();

    // Filter by network if active — also trim grouped token chains
    if (networkFilter != null) {
      filteredGroups = filteredGroups
        .where((g) => g.chains.any((wb) =>
          wb.balance.network.toLowerCase() == networkFilter))
        .map((g) {
          final filtered = g.chains.where((wb) =>
            wb.balance.network.toLowerCase() == networkFilter).toList();
          if (filtered.length == g.chains.length) return g;
          double total = 0;
          for (final wb in filtered) {
            total += double.tryParse(wb.balance.balance) ?? 0.0;
          }
          return GroupedToken(
            token: g.token,
            totalBalance: total,
            chains: filtered,
          );
        })
        .toList();
    }

    // Filter zero balances if setting enabled
    if (walletSettings.hideZeroBalances) {
      filteredGroups = filteredGroups.where((g) => g.totalBalance > 0).toList();
    }

    return filteredGroups.isEmpty
        ? Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 16),
            child: Center(
              child: Column(
                children: [
                  FaIcon(FontAwesomeIcons.coins, size: 32,
                    color: theme.colorScheme.onSurface.withValues(alpha: 0.2)),
                  const SizedBox(height: 8),
                  Text(
                    walletSettings.hideZeroBalances
                        ? 'No non-zero balances'
                        : 'No balances',
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: theme.colorScheme.onSurface.withValues(alpha: 0.4)),
                  ),
                ],
              ),
            ),
          )
        : Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                child: Row(
                  children: [
                    Text(
                      'Assets',
                      style: theme.textTheme.titleMedium?.copyWith(fontWeight: FontWeight.bold),
                    ),
                    const SizedBox(width: 8),
                    DnaChip(label: '${filteredGroups.length}'),
                  ],
                ),
              ),
              ...filteredGroups.map((group) {
                if (group.isMultiChain) {
                  return _GroupedTokenTile(groupedToken: group);
                } else {
                  return _BalanceTile(walletBalance: group.chains.first);
                }
              }),
            ],
          );
  }
}

/// Tile for a token that exists on multiple chains (e.g., USDT on ETH+SOL+TRX)
class _GroupedTokenTile extends ConsumerWidget {
  final GroupedToken groupedToken;

  const _GroupedTokenTile({required this.groupedToken});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final token = groupedToken.token;
    final iconPath = getTokenIconPath(token);
    final hideBalances = ref.watch(walletSettingsProvider).hideBalances;

    final tokenColor = _getGroupedTokenColor(token);

    return DnaCard(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
      onTap: () => _showChainBreakdown(context, ref),
      child: Row(
        children: [
          // Token icon with glow ring
          Container(
            width: 44,
            height: 44,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              boxShadow: [
                BoxShadow(
                  color: tokenColor.withValues(alpha: 0.2),
                  blurRadius: 8,
                  spreadRadius: 1,
                ),
              ],
            ),
            child: Container(
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                border: Border.all(
                  color: tokenColor.withValues(alpha: 0.3),
                  width: 1.5,
                ),
                color: tokenColor.withValues(alpha: 0.08),
              ),
              child: iconPath != null
                  ? Padding(
                      padding: const EdgeInsets.all(8),
                      child: buildCryptoIcon(iconPath),
                    )
                  : Center(
                      child: Text(
                        token.isNotEmpty ? token[0].toUpperCase() : '?',
                        style: TextStyle(
                          color: tokenColor,
                          fontWeight: FontWeight.bold,
                          fontSize: 16,
                        ),
                      ),
                    ),
            ),
          ),
          const SizedBox(width: 14),
          // Token name + chain count
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(token,
                  style: theme.textTheme.titleSmall?.copyWith(
                    fontWeight: FontWeight.w600, fontSize: 15)),
                const SizedBox(height: 2),
                Text('${groupedToken.chains.length} chains',
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurface.withValues(alpha: 0.4),
                    fontSize: 12)),
              ],
            ),
          ),
          // Total balance
          Column(
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              Text(
                hideBalances ? '*****' : _truncateBalance(groupedToken.totalBalance.toStringAsFixed(6)),
                style: theme.textTheme.titleSmall?.copyWith(fontWeight: FontWeight.bold),
              ),
              if (!hideBalances) Builder(builder: (context) {
                // Sum USD values across chains
                double totalUsd = 0;
                for (final wb in groupedToken.chains) {
                  final usd = ref.watch(tokenUsdValueProvider(
                    (token: wb.balance.token, balance: wb.balance.balance)));
                  if (usd != null) totalUsd += usd;
                }
                if (totalUsd > 0) {
                  return Text('\$${_formatUsdValue(totalUsd)}',
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: theme.colorScheme.onSurface.withValues(alpha: 0.5)));
                }
                return const SizedBox.shrink();
              }),
            ],
          ),
          const SizedBox(width: 8),
          FaIcon(FontAwesomeIcons.chevronRight, size: 14,
            color: theme.colorScheme.onSurface.withValues(alpha: 0.3)),
        ],
      ),
    );
  }

  void _showChainBreakdown(BuildContext context, WidgetRef ref) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      builder: (context) => DraggableScrollableSheet(
        initialChildSize: 0.5,
        maxChildSize: 0.8,
        minChildSize: 0.3,
        expand: false,
        builder: (context, scrollController) {
          final theme = Theme.of(context);
          return Container(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Center(
                  child: Container(
                    width: 40, height: 4,
                    decoration: BoxDecoration(
                      color: theme.colorScheme.onSurface.withValues(alpha: 0.2),
                      borderRadius: BorderRadius.circular(2)),
                  ),
                ),
                const SizedBox(height: 16),
                Text('${groupedToken.token} — ${_truncateBalance(groupedToken.totalBalance.toStringAsFixed(6))} total',
                  style: theme.textTheme.titleLarge?.copyWith(fontWeight: FontWeight.bold)),
                const SizedBox(height: 16),
                Expanded(
                  child: ListView.builder(
                    controller: scrollController,
                    itemCount: groupedToken.chains.length,
                    itemBuilder: (context, index) {
                      final wb = groupedToken.chains[index];
                      return _BalanceTile(walletBalance: wb);
                    },
                  ),
                ),
              ],
            ),
          );
        },
      ),
    );
  }

  Color _getGroupedTokenColor(String token) {
    switch (token.toUpperCase()) {
      case 'USDT':
        return const Color(0xFF50AF95); // Tether green (official)
      case 'USDC':
        return const Color(0xFF2775CA); // USD Coin blue (official)
      default:
        return DnaColors.textInfo;
    }
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
    final hideBalances = ref.watch(walletSettingsProvider).hideBalances;
    final tokenColor = _getTokenColor(balance.token);

    return DnaCard(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
      onTap: () => _showTokenDetails(context, ref),
      child: Row(
        children: [
          // Token icon with glow ring
          Container(
            width: 44,
            height: 44,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              boxShadow: [
                BoxShadow(
                  color: tokenColor.withValues(alpha: 0.2),
                  blurRadius: 8,
                  spreadRadius: 1,
                ),
              ],
            ),
            child: Container(
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                border: Border.all(
                  color: tokenColor.withValues(alpha: 0.3),
                  width: 1.5,
                ),
                color: tokenColor.withValues(alpha: 0.08),
              ),
              child: iconPath != null
                  ? Padding(
                      padding: const EdgeInsets.all(8),
                      child: buildCryptoIcon(iconPath),
                    )
                  : Center(
                      child: Text(
                        balance.token.isNotEmpty ? balance.token[0].toUpperCase() : '?',
                        style: TextStyle(
                          color: tokenColor,
                          fontWeight: FontWeight.bold,
                          fontSize: 16,
                        ),
                      ),
                    ),
            ),
          ),
          const SizedBox(width: 14),
          // Token name + network
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  balance.token,
                  style: theme.textTheme.titleSmall?.copyWith(
                    fontWeight: FontWeight.w600,
                    fontSize: 15,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  getNetworkDisplayLabel(balance.network),
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurface.withValues(alpha: 0.4),
                    fontSize: 12,
                  ),
                ),
              ],
            ),
          ),
          // Balance + USD value + 24h change + chevron
          Column(
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              Text(
                hideBalances ? '*****' : _truncateBalance(balance.balance),
                style: theme.textTheme.titleSmall?.copyWith(fontWeight: FontWeight.bold),
              ),
              Builder(builder: (context) {
                if (hideBalances) {
                  return Text(
                    '\$*****',
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: theme.colorScheme.onSurface.withValues(alpha: 0.5),
                    ),
                  );
                }
                final usdValue = ref.watch(tokenUsdValueProvider((token: balance.token, balance: balance.balance)));
                final prices = ref.watch(priceProvider).valueOrNull;
                final change24h = prices?[balance.token.toUpperCase()]?.changePercent24h;
                if (usdValue != null && usdValue > 0) {
                  return Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Text(
                        '\$${_formatUsdValue(usdValue)}',
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: theme.colorScheme.onSurface.withValues(alpha: 0.5),
                        ),
                      ),
                      if (change24h != null && change24h != 0.0) ...[
                        const SizedBox(width: 6),
                        _Change24hBadge(changePercent: change24h),
                      ],
                    ],
                  );
                }
                return const SizedBox.shrink();
              }),
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

  void _showTokenDetails(BuildContext context, WidgetRef ref) {
    final balance = walletBalance.balance;

    // Invalidate to fetch fresh data when opening
    ref.invalidate(transactionsProvider((walletIndex: walletBalance.walletIndex, network: balance.network)));
    ref.invalidate(balancesProvider(walletBalance.walletIndex));

    // Look up the correct address for this token's network
    final wallets = ref.read(walletsProvider).valueOrNull ?? [];
    final networkAddress = getWalletAddressByNetwork(wallets, balance.network)
        ?? walletBalance.wallet.address;

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      builder: (context) => _TokenDetailSheet(
        walletIndex: walletBalance.walletIndex,
        walletAddress: networkAddress,
        token: balance.token,
        network: balance.network,
        initialBalance: balance.balance,
      ),
    );
  }

  Color _getTokenColor(String token) {
    switch (token.toUpperCase()) {
      case 'CPUNK':
        return const Color(0xFF00E5A0); // CPUNK vibrant cyan-green
      case 'CELL':
        return const Color(0xFF7B3FE4); // Cellframe purple
      case 'ETH':
        return const Color(0xFF627EEA); // Ethereum blue
      case 'SOL':
        return const Color(0xFF14F195); // Solana green
      case 'TRX':
        return const Color(0xFFEF0027); // TRON red
      case 'USDT':
        return const Color(0xFF50AF95); // Tether green
      case 'USDC':
        return const Color(0xFF2775CA); // USD Coin blue
      case 'KEL':
        return const Color(0xFFFF8C42); // KEL orange
      case 'NYS':
        return const Color(0xFFE040FB); // NYS magenta
      case 'QEVM':
        return const Color(0xFF4FC3F7); // QEVM light blue
      default:
        return DnaColors.textInfo;
    }
  }
}

/// 24h price change badge — green ▲ for positive, red ▼ for negative
/// Uses opaque backgrounds with white text for guaranteed readability
/// on gradient headers, dark mode, and light mode.
class _Change24hBadge extends StatelessWidget {
  final double changePercent;
  final bool light; // true = on gradient header background

  const _Change24hBadge({required this.changePercent, this.light = false});

  @override
  Widget build(BuildContext context) {
    final isPositive = changePercent > 0;
    final arrow = isPositive ? '▲' : '▼';
    final sign = isPositive ? '+' : '';

    // Opaque backgrounds — readable on any surface (gradient, dark, light)
    final bgColor = isPositive
        ? const Color(0xFF1B5E20) // Dark green background
        : const Color(0xFFB71C1C); // Dark red background

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        color: bgColor.withValues(alpha: light ? 0.85 : 0.80),
        borderRadius: BorderRadius.circular(6),
      ),
      child: Text(
        '$arrow $sign${changePercent.toStringAsFixed(1)}%',
        style: const TextStyle(
          color: Colors.white,
          fontSize: 11,
          fontWeight: FontWeight.w600,
        ),
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
  bool _isLoadingGas = false;

  // Cellframe network fees (validator fee varies by speed, network fee is fixed)
  static const double _cellframeNetworkFee = 0.002;
  static const double _cellframeValidatorSlow = 0.0001;   // slow
  static const double _cellframeValidatorNormal = 0.01;   // normal
  static const double _cellframeValidatorFast = 0.05;     // fast

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
      // Cellframe: only subtract fee when sending CELL (native token)
      // CPUNK and other tokens: fees are paid in CELL, not the token itself
      if (_selectedToken == 'CELL') {
        double validatorFee;
        switch (_selectedGasSpeed) {
          case 0:
            validatorFee = _cellframeValidatorSlow;
            break;
          case 1:
            validatorFee = _cellframeValidatorNormal;
            break;
          case 2:
            validatorFee = _cellframeValidatorFast;
            break;
          default:
            validatorFee = _cellframeValidatorNormal;
        }
        final totalFee = validatorFee + _cellframeNetworkFee;
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
    _selectedNetwork = widget.preselectedNetwork ?? 'Cellframe';
    if (_selectedNetwork == 'Ethereum') {
      _fetchGasEstimates();
    }
  }

  Future<void> _fetchGasEstimates() async {
    if (!mounted) return;
    setState(() => _isLoadingGas = true);
    try {
      final engine = await ref.read(engineProvider.future);
      final estimates = await engine.estimateEthGasAsync();
      if (mounted) {
        setState(() {
          _gasFee0 = estimates.slow.feeEth;
          _gasFee1 = estimates.normal.feeEth;
          _gasFee2 = estimates.fast.feeEth;
          _isLoadingGas = false;
        });
      }
    } catch (_) {
      if (mounted) {
        setState(() => _isLoadingGas = false);
      }
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
    } else if (network == 'bsc') {
      // BSC uses same address as ETH (EVM-compatible)
      return profile.eth.isNotEmpty ? profile.eth : null;
    } else {
      // Cellframe (default)
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
    } else if (network == 'bsc') {
      return 'BNB';
    } else {
      return 'Cellframe';
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

      // Get display name if we don't have one (v0.6.24: displayName removed from profile)
      String resolvedName;
      if (displayName != null && displayName.isNotEmpty) {
        resolvedName = displayName;
      } else {
        try {
          resolvedName = await engine.getDisplayName(fingerprint);
        } catch (_) {
          resolvedName = '${fingerprint.substring(0, 8)}...';
        }
      }

      if (!mounted || thisRequestId != _resolveRequestId) return;

      setState(() {
        _isResolving = false;
        _resolvedAddress = walletAddress;
        _resolvedContactName = resolvedName;
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
                            backgroundColor: Theme.of(context).colorScheme.primary.withAlpha(50),
                            child: Text(
                              contact.displayName.isNotEmpty
                                  ? contact.displayName[0].toUpperCase()
                                  : '?',
                              style: TextStyle(color: Theme.of(context).colorScheme.primary),
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
                AppLocalizations.of(context).walletSend,
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
                        labelText: AppLocalizations.of(context).walletRecipientAddress,
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
                        labelText: AppLocalizations.of(context).walletAmount,
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
                        child: Text(AppLocalizations.of(context).walletMax),
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
                      key: ValueKey('token_$_selectedNetwork'),
                      initialValue: _selectedToken,
                      decoration: const InputDecoration(labelText: 'Token'),
                      items: _getTokenItems(),
                      onChanged: (v) => setState(() => _selectedToken = v ?? 'CPUNK'),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: DropdownButtonFormField<String>(
                      initialValue: _selectedNetwork,
                      decoration: const InputDecoration(labelText: 'Network'),
                      items: _getNetworkItems(),
                      onChanged: (v) {
                        final newNetwork = v ?? 'Cellframe';
                        setState(() {
                          _selectedNetwork = newNetwork;
                          // Reset token to default for the new network
                          if (widget.preselectedToken == null) {
                            _selectedToken = _defaultTokenForNetwork(newNetwork);
                          }
                        });
                        // Fetch gas estimates when switching to Ethereum
                        if (newNetwork == 'Ethereum') {
                          _fetchGasEstimates();
                        }
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
                      isLoading: _isLoadingGas,
                      selected: _selectedGasSpeed == 0,
                      onSelected: () => setState(() => _selectedGasSpeed = 0),
                    ),
                    const SizedBox(width: 8),
                    _GasSpeedChip(
                      label: 'Normal',
                      sublabel: _gasFee1 != null ? '${_gasFee1!} ETH' : '1.0x',
                      isLoading: _isLoadingGas,
                      selected: _selectedGasSpeed == 1,
                      onSelected: () => setState(() => _selectedGasSpeed = 1),
                    ),
                    const SizedBox(width: 8),
                    _GasSpeedChip(
                      label: 'Fast',
                      sublabel: _gasFee2 != null ? '${_gasFee2!} ETH' : '1.5x',
                      isLoading: _isLoadingGas,
                      selected: _selectedGasSpeed == 2,
                      onSelected: () => setState(() => _selectedGasSpeed = 2),
                    ),
                  ],
                ),
              ],
              // Transaction speed selector for Cellframe
              if (_selectedNetwork == 'Cellframe') ...[
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
                      sublabel: '${(_cellframeValidatorSlow + _cellframeNetworkFee).toStringAsFixed(4)} CELL',
                      selected: _selectedGasSpeed == 0,
                      onSelected: () => setState(() => _selectedGasSpeed = 0),
                    ),
                    const SizedBox(width: 8),
                    _GasSpeedChip(
                      label: 'Normal',
                      sublabel: '${(_cellframeValidatorNormal + _cellframeNetworkFee).toStringAsFixed(3)} CELL',
                      selected: _selectedGasSpeed == 1,
                      onSelected: () => setState(() => _selectedGasSpeed = 1),
                    ),
                    const SizedBox(width: 8),
                    _GasSpeedChip(
                      label: 'Fast',
                      sublabel: '${(_cellframeValidatorFast + _cellframeNetworkFee).toStringAsFixed(3)} CELL',
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
                    : Text(AppLocalizations.of(context).walletSend),
              ),
            ],
          ),
        ),
      ),
    );
  }

  List<DropdownMenuItem<String>> _getTokenItems() {
    // If opened from token detail sheet, lock to that token
    if (widget.preselectedToken != null) {
      return [
        DropdownMenuItem(value: _selectedToken, child: Text(_selectedToken)),
      ];
    }
    // Main Send button: show all tokens for the selected network
    final network = _selectedNetwork.toLowerCase();
    if (network == 'ethereum') {
      return const [
        DropdownMenuItem(value: 'ETH', child: Text('ETH')),
        DropdownMenuItem(value: 'USDT', child: Text('USDT')),
        DropdownMenuItem(value: 'USDC', child: Text('USDC')),
      ];
    }
    if (network == 'solana') {
      return const [
        DropdownMenuItem(value: 'SOL', child: Text('SOL')),
        DropdownMenuItem(value: 'USDT', child: Text('USDT')),
        DropdownMenuItem(value: 'USDC', child: Text('USDC')),
      ];
    }
    if (network == 'tron') {
      return const [
        DropdownMenuItem(value: 'TRX', child: Text('TRX')),
        DropdownMenuItem(value: 'USDT', child: Text('USDT')),
        DropdownMenuItem(value: 'USDC', child: Text('USDC')),
      ];
    }
    // Cellframe
    return const [
      DropdownMenuItem(value: 'CPUNK', child: Text('CPUNK')),
      DropdownMenuItem(value: 'CELL', child: Text('CELL')),
      DropdownMenuItem(value: 'KEL', child: Text('KEL')),
      DropdownMenuItem(value: 'NYS', child: Text('NYS')),
      DropdownMenuItem(value: 'QEVM', child: Text('QEVM')),
    ];
  }

  List<DropdownMenuItem<String>> _getNetworkItems() {
    // If opened from token detail sheet, lock to that network
    if (widget.preselectedNetwork != null) {
      final label = _networkDisplayLabel(_selectedNetwork);
      return [
        DropdownMenuItem(value: _selectedNetwork, child: Text(label)),
      ];
    }
    // Main Send button: show all networks
    return const [
      DropdownMenuItem(value: 'Cellframe', child: Text('CF20')),
      DropdownMenuItem(value: 'Ethereum', child: Text('ERC20')),
      DropdownMenuItem(value: 'Solana', child: Text('SPL')),
      DropdownMenuItem(value: 'Tron', child: Text('TRC20')),
      DropdownMenuItem(value: 'BSC', child: Text('BEP20')),
    ];
  }

  String _networkDisplayLabel(String network) {
    switch (network.toLowerCase()) {
      case 'ethereum': return 'ERC20';
      case 'solana': return 'SPL';
      case 'tron': return 'TRC20';
      case 'bsc': return 'BEP20';
      default: return 'CF20';
    }
  }

  /// Default token for a given network
  String _defaultTokenForNetwork(String network) {
    switch (network.toLowerCase()) {
      case 'ethereum': return 'ETH';
      case 'solana': return 'SOL';
      case 'tron': return 'TRX';
      default: return 'CPUNK';
    }
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
                    _selectedNetwork.toLowerCase() == 'tron' ? 'tron' : 'cellframe';

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
          SnackBar(content: Text(AppLocalizations.of(context).walletSendSuccess)),
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
            content: Text(AppLocalizations.of(context).walletSendFailed(e.toString())),
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
      transactionsProvider((walletIndex: walletIndex, network: network)),
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
              // Gradient header
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(20),
                decoration: const BoxDecoration(
                  gradient: DnaGradients.primaryVertical,
                ),
                child: Column(
                  children: [
                    Row(
                      children: [
                        _buildTokenIcon(token, 48),
                        const SizedBox(width: 12),
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                '${_truncateBalance(balance)} $token',
                                style: const TextStyle(color: Colors.white, fontSize: 24, fontWeight: FontWeight.bold),
                              ),
                              Builder(builder: (context) {
                                final usdValue = ref.watch(tokenUsdValueProvider((token: token, balance: balance)));
                                if (usdValue != null && usdValue > 0) {
                                  return Text(
                                    '\u2248 \$${_formatUsdValue(usdValue)}',
                                    style: const TextStyle(color: Colors.white70, fontSize: 14),
                                  );
                                }
                                return const SizedBox.shrink();
                              }),
                              Text(
                                getNetworkDisplayLabel(network),
                                style: const TextStyle(color: Colors.white70, fontSize: 13),
                              ),
                            ],
                          ),
                        ),
                        IconButton(
                          icon: const FaIcon(FontAwesomeIcons.arrowsRotate, color: Colors.white70),
                          onPressed: () {
                            ref.invalidate(balancesProvider(walletIndex));
                            ref.invalidate(transactionsProvider((walletIndex: walletIndex, network: network)));
                          },
                          tooltip: 'Refresh',
                        ),
                      ],
                    ),
                    const SizedBox(height: 16),
                    // Send button on gradient
                    SizedBox(
                      width: double.infinity,
                      child: ElevatedButton.icon(
                        onPressed: () => _showSend(context, ref, balance),
                        icon: const FaIcon(FontAwesomeIcons.arrowUp, size: 16, color: Colors.white),
                        label: Text(AppLocalizations.of(context).walletSendTitle(token), style: const TextStyle(color: Colors.white)),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: Colors.white.withValues(alpha: 0.2),
                          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(DnaSpacing.radiusMd)),
                          padding: const EdgeInsets.symmetric(vertical: 12),
                        ),
                      ),
                    ),
                  ],
                ),
              ),
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
                            Text('Address', style: theme.textTheme.labelSmall?.copyWith(color: theme.colorScheme.primary)),
                            const SizedBox(height: 4),
                            Text(walletAddress, style: theme.textTheme.bodySmall?.copyWith(fontFamily: 'monospace'), maxLines: 2, overflow: TextOverflow.ellipsis),
                          ],
                        ),
                      ),
                      IconButton(
                        icon: const FaIcon(FontAwesomeIcons.copy, size: 18),
                        onPressed: () {
                          Clipboard.setData(ClipboardData(text: walletAddress));
                          ScaffoldMessenger.of(context).showSnackBar(
                            SnackBar(
                              content: Row(
                                children: [
                                  FaIcon(FontAwesomeIcons.circleCheck,
                                      size: 18, color: Colors.white),
                                  const SizedBox(width: 10),
                                  Text(AppLocalizations.of(context).walletAddressCopied,
                                      style: const TextStyle(fontSize: 15)),
                                ],
                              ),
                              duration: const Duration(seconds: 2),
                              behavior: SnackBarBehavior.floating,
                              margin: const EdgeInsets.all(16),
                              shape: RoundedRectangleBorder(
                                  borderRadius: BorderRadius.circular(10)),
                            ),
                          );
                        },
                        tooltip: 'Copy address',
                      ),
                    ],
                  ),
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
                              AppLocalizations.of(context).walletNoTransactions,
                              style: theme.textTheme.bodyMedium,
                            ),
                          ],
                        ),
                      );
                    }

                    // Build grouped list with date separators
                    final groupedItems = _buildDateGroupedItems(filtered, context);
                    return ListView.builder(
                      controller: scrollController,
                      itemCount: groupedItems.length,
                      itemBuilder: (context, index) {
                        final item = groupedItems[index];
                        if (item is String) {
                          // Date separator
                          return Padding(
                            padding: const EdgeInsets.fromLTRB(16, 12, 16, 4),
                            child: Text(
                              item,
                              style: theme.textTheme.labelMedium?.copyWith(
                                color: theme.colorScheme.onSurface.withValues(alpha: 0.5),
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                          );
                        }
                        final tx = item as Transaction;
                        return _TransactionTile(transaction: tx, network: network);
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

  /// Build a token icon widget (SVG or fallback letter avatar)
  Widget _buildTokenIcon(String tokenName, double size) {
    final iconPath = getTokenIconPath(tokenName);
    if (iconPath != null) {
      return SizedBox(
        width: size,
        height: size,
        child: buildCryptoIcon(iconPath),
      );
    }
    return CircleAvatar(
      backgroundColor: Colors.white.withValues(alpha: 0.2),
      radius: size / 2,
      child: Text(
        tokenName.isNotEmpty ? tokenName[0].toUpperCase() : '?',
        style: const TextStyle(
          color: Colors.white,
          fontWeight: FontWeight.bold,
          fontSize: 20,
        ),
      ),
    );
  }

  /// Group transactions by date with separator labels
  List<dynamic> _buildDateGroupedItems(List<Transaction> txs, BuildContext context) {
    final l10n = AppLocalizations.of(context);
    final now = DateTime.now();
    final today = DateTime(now.year, now.month, now.day);
    final yesterday = today.subtract(const Duration(days: 1));
    final weekAgo = today.subtract(const Duration(days: 7));

    final items = <dynamic>[];
    String? lastGroup;

    for (final tx in txs) {
      final ts = int.tryParse(tx.timestamp);
      final txDate = ts != null && ts > 0
          ? DateTime.fromMillisecondsSinceEpoch(ts * 1000)
          : null;

      String group;
      if (txDate == null) {
        group = l10n.walletTxEarlier;
      } else {
        final txDay = DateTime(txDate.year, txDate.month, txDate.day);
        if (txDay == today) {
          group = l10n.walletTxToday;
        } else if (txDay == yesterday) {
          group = l10n.walletTxYesterday;
        } else if (txDay.isAfter(weekAgo)) {
          group = l10n.walletTxThisWeek;
        } else {
          group = l10n.walletTxEarlier;
        }
      }

      if (group != lastGroup) {
        items.add(group);
        lastGroup = group;
      }
      items.add(tx);
    }

    return items;
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

}

class _TransactionTile extends StatelessWidget {
  final Transaction transaction;
  final String network;

  const _TransactionTile({required this.transaction, required this.network});

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
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('${transaction.amount} ${transaction.token}', style: theme.textTheme.titleSmall?.copyWith(fontWeight: FontWeight.bold)),
                const SizedBox(height: 2),
                if (transaction.resolvedName != null) ...[
                  Text(transaction.resolvedName!, style: theme.textTheme.bodySmall?.copyWith(fontWeight: FontWeight.w600)),
                  Text(_formatAddress(transaction.otherAddress), style: theme.textTheme.labelSmall?.copyWith(fontFamily: 'monospace', color: theme.colorScheme.outline)),
                ] else
                  Text(_formatAddress(transaction.otherAddress), style: theme.textTheme.bodySmall?.copyWith(fontFamily: 'monospace')),
                Text(_formatTimestamp(transaction.timestamp), style: theme.textTheme.labelSmall),
              ],
            ),
          ),
          _StatusChip(status: transaction.status),
        ],
      ),
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
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (context) => _TransactionDetailSheet(
        transaction: transaction,
        network: network,
      ),
    );
  }
}

/// Modern transaction detail bottom sheet
class _TransactionDetailSheet extends ConsumerWidget {
  final Transaction transaction;
  final String network;

  const _TransactionDetailSheet({
    required this.transaction,
    required this.network,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final isReceived = transaction.direction.toLowerCase() == 'received';
    final isDenied = ['FAILED', 'REJECTED', 'DENIED'].contains(transaction.status.toUpperCase());
    final addressInBook = ref.watch(addressExistsProvider((transaction.otherAddress, network)));

    // Direction-based gradient: blue=send, green=receive, orange=denied
    final LinearGradient headerGradient;
    if (isDenied) {
      headerGradient = const LinearGradient(
        begin: Alignment.topCenter,
        end: Alignment.bottomCenter,
        colors: [Color(0xFFE8871E), Color(0xFFD45B0A)],
      );
    } else if (isReceived) {
      headerGradient = const LinearGradient(
        begin: Alignment.topCenter,
        end: Alignment.bottomCenter,
        colors: [Color(0xFF00B87A), Color(0xFF00875A)],
      );
    } else {
      headerGradient = DnaGradients.primaryVertical;
    }

    final l10n = AppLocalizations.of(context);

    // Header subtitle
    final String headerSubtitle;
    if (isDenied) {
      headerSubtitle = l10n.txDetailDenied;
    } else if (isReceived) {
      headerSubtitle = l10n.txDetailReceived;
    } else {
      headerSubtitle = l10n.txDetailSent;
    }

    return Container(
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        borderRadius: const BorderRadius.vertical(top: Radius.circular(DnaSpacing.radiusXl)),
      ),
      child: SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            // Handle bar
            Container(
              margin: const EdgeInsets.only(top: DnaSpacing.sm),
              width: 40,
              height: 4,
              decoration: BoxDecoration(
                color: theme.dividerColor,
                borderRadius: BorderRadius.circular(2),
              ),
            ),
            // Gradient header — color varies by direction/status
            Container(
              width: double.infinity,
              margin: const EdgeInsets.all(DnaSpacing.lg),
              padding: const EdgeInsets.symmetric(horizontal: DnaSpacing.xl, vertical: DnaSpacing.xl + 4),
              decoration: BoxDecoration(
                gradient: headerGradient,
                borderRadius: BorderRadius.circular(DnaSpacing.radiusLg),
              ),
              child: Column(
                children: [
                  // Big amount
                  Text(
                    '${transaction.amount} ${transaction.token}',
                    style: const TextStyle(
                      color: Colors.white,
                      fontSize: 32,
                      fontWeight: FontWeight.w800,
                      letterSpacing: -0.5,
                    ),
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: DnaSpacing.sm),
                  // Subtitle (Sent / Received / Denied)
                  Text(
                    headerSubtitle,
                    style: TextStyle(
                      color: Colors.white.withValues(alpha: 0.85),
                      fontSize: 15,
                      fontWeight: FontWeight.w500,
                    ),
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: DnaSpacing.sm),
                  _StatusChip(status: transaction.status),
                ],
              ),
            ),
            // Detail rows
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: DnaSpacing.lg),
              child: Column(
                children: [
                  _buildDetailRow(
                    context,
                    icon: FontAwesomeIcons.user,
                    label: isReceived ? l10n.txDetailFrom : l10n.txDetailTo,
                    value: transaction.resolvedName ?? _formatAddress(transaction.otherAddress),
                    subtitle: transaction.resolvedName != null ? transaction.otherAddress : null,
                    monospace: transaction.resolvedName == null,
                    onTap: () => _copyAndNotify(context, transaction.otherAddress, l10n.txDetailAddressCopied),
                  ),
                  _buildDivider(theme),
                  _buildDetailRow(
                    context,
                    icon: FontAwesomeIcons.hashtag,
                    label: l10n.txDetailTransactionHash,
                    value: _formatHash(transaction.txHash),
                    monospace: true,
                    onTap: () => _copyAndNotify(context, transaction.txHash, l10n.txDetailHashCopied),
                  ),
                  _buildDivider(theme),
                  _buildDetailRow(
                    context,
                    icon: FontAwesomeIcons.clock,
                    label: l10n.txDetailTime,
                    value: _formatTimestamp(transaction.timestamp),
                  ),
                  _buildDivider(theme),
                  _buildDetailRow(
                    context,
                    icon: FontAwesomeIcons.networkWired,
                    label: l10n.txDetailNetwork,
                    value: getNetworkDisplayLabel(network),
                  ),
                ],
              ),
            ),
            const SizedBox(height: DnaSpacing.xl),
            // Action buttons
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: DnaSpacing.lg),
              child: Column(
                children: [
                  // Add to Address Book button (only if not already in book and address is not ours)
                  if (!addressInBook && transaction.otherAddress.isNotEmpty)
                    SizedBox(
                      width: double.infinity,
                      child: OutlinedButton.icon(
                        onPressed: () => _addToAddressBook(context, ref),
                        icon: const FaIcon(FontAwesomeIcons.addressBook, size: 16),
                        label: Text(l10n.txDetailAddToAddressBook),
                        style: OutlinedButton.styleFrom(
                          padding: const EdgeInsets.symmetric(vertical: DnaSpacing.md),
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(DnaSpacing.radiusMd),
                          ),
                        ),
                      ),
                    ),
                  if (!addressInBook && transaction.otherAddress.isNotEmpty)
                    const SizedBox(height: DnaSpacing.sm),
                  SizedBox(
                    width: double.infinity,
                    child: TextButton(
                      onPressed: () => Navigator.pop(context),
                      child: Text(l10n.txDetailClose),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: DnaSpacing.lg),
          ],
        ),
      ),
    );
  }

  Widget _buildDetailRow(
    BuildContext context, {
    required IconData icon,
    required String label,
    required String value,
    String? subtitle,
    bool monospace = false,
    VoidCallback? onTap,
  }) {
    final theme = Theme.of(context);

    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(DnaSpacing.radiusSm),
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: DnaSpacing.md),
        child: Row(
          children: [
            FaIcon(icon, size: 14, color: theme.colorScheme.primary),
            const SizedBox(width: DnaSpacing.md),
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
                      fontWeight: subtitle != null ? FontWeight.w600 : null,
                    ),
                  ),
                  if (subtitle != null)
                    Text(
                      _formatAddress(subtitle),
                      style: theme.textTheme.labelSmall?.copyWith(
                        fontFamily: 'monospace',
                        color: theme.colorScheme.outline,
                      ),
                    ),
                ],
              ),
            ),
            if (onTap != null)
              FaIcon(FontAwesomeIcons.copy, size: 12, color: theme.colorScheme.outline),
          ],
        ),
      ),
    );
  }

  Widget _buildDivider(ThemeData theme) {
    return Divider(height: 1, color: theme.dividerColor);
  }

  String _formatAddress(String address) {
    if (address.isEmpty) return '-';
    if (address.length <= 20) return address;
    return '${address.substring(0, 10)}...${address.substring(address.length - 8)}';
  }

  String _formatHash(String hash) {
    if (hash.isEmpty) return '-';
    if (hash.length <= 20) return hash;
    return '${hash.substring(0, 10)}...${hash.substring(hash.length - 8)}';
  }

  String _formatTimestamp(String timestamp) {
    if (timestamp.isEmpty) return '-';
    final ts = int.tryParse(timestamp);
    if (ts != null && ts > 0) {
      final date = DateTime.fromMillisecondsSinceEpoch(ts * 1000);
      return '${date.year}-${date.month.toString().padLeft(2, '0')}-${date.day.toString().padLeft(2, '0')} '
             '${date.hour.toString().padLeft(2, '0')}:${date.minute.toString().padLeft(2, '0')}';
    }
    return timestamp;
  }

  void _copyAndNotify(BuildContext context, String text, String message) {
    Clipboard.setData(ClipboardData(text: text));
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(message), duration: const Duration(seconds: 2)),
    );
  }

  void _addToAddressBook(BuildContext context, WidgetRef ref) async {
    final result = await showDialog<AddressDialogResult>(
      context: context,
      builder: (context) => AddressDialog.prefilled(
        address: transaction.otherAddress,
        network: network,
      ),
    );

    if (result != null && context.mounted) {
      final l10n = AppLocalizations.of(context);
      try {
        await ref.read(addressBookProvider.notifier).addAddress(
              address: result.address,
              label: result.label,
              network: result.network,
              notes: result.notes,
            );
        if (context.mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text(l10n.txDetailAddedToAddressBook(result.label))),
          );
        }
      } catch (e) {
        if (context.mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text(l10n.txDetailFailedToAdd('$e')), backgroundColor: Colors.red),
          );
        }
      }
    }
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
  final bool isLoading;
  final VoidCallback onSelected;

  const _GasSpeedChip({
    required this.label,
    required this.sublabel,
    required this.selected,
    required this.onSelected,
    this.isLoading = false,
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
              if (isLoading)
                SizedBox(
                  height: 14,
                  width: 14,
                  child: CircularProgressIndicator(
                    strokeWidth: 1.5,
                    color: selected
                        ? theme.colorScheme.primary.withAlpha(179)
                        : theme.colorScheme.onSurface.withAlpha(128),
                  ),
                )
              else
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

