// Wallet Settings Provider - Wallet display preferences
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

const _kHideZeroBalances = 'wallet_hide_zero_balances';
const _kHideBalances = 'wallet_hide_balances';
const _kActiveChains = 'wallet_active_chains';

/// All toggleable chains (DNAC is always active and not in this list)
const allToggleableChains = ['bsc', 'cellframe', 'ethereum', 'solana', 'tron'];

/// State for wallet display settings
class WalletSettingsState {
  final bool hideZeroBalances;
  final bool hideBalances;
  final Set<String> activeChains;

  const WalletSettingsState({
    this.hideZeroBalances = false,
    this.hideBalances = false,
    this.activeChains = const {'bsc', 'cellframe', 'ethereum', 'solana', 'tron'},
  });

  /// Whether a chain is active. DNAC is always active.
  bool isChainActive(String chain) =>
      chain == 'dnac' || activeChains.contains(chain);

  WalletSettingsState copyWith({
    bool? hideZeroBalances,
    bool? hideBalances,
    Set<String>? activeChains,
  }) => WalletSettingsState(
        hideZeroBalances: hideZeroBalances ?? this.hideZeroBalances,
        hideBalances: hideBalances ?? this.hideBalances,
        activeChains: activeChains ?? this.activeChains,
      );
}

/// Notifier for wallet display settings
class WalletSettingsNotifier extends StateNotifier<WalletSettingsState> {
  WalletSettingsNotifier() : super(const WalletSettingsState()) {
    _load();
  }

  Future<void> _load() async {
    final prefs = await SharedPreferences.getInstance();
    final chainsList = prefs.getStringList(_kActiveChains);
    state = WalletSettingsState(
      hideZeroBalances: prefs.getBool(_kHideZeroBalances) ?? false,
      hideBalances: prefs.getBool(_kHideBalances) ?? false,
      activeChains: chainsList != null
          ? chainsList.toSet()
          : const {'bsc', 'cellframe', 'ethereum', 'solana', 'tron'},
    );
  }

  Future<void> setHideZeroBalances(bool value) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool(_kHideZeroBalances, value);
    state = state.copyWith(hideZeroBalances: value);
  }

  Future<void> toggleHideBalances() async {
    final prefs = await SharedPreferences.getInstance();
    final newValue = !state.hideBalances;
    await prefs.setBool(_kHideBalances, newValue);
    state = state.copyWith(hideBalances: newValue);
  }

  Future<void> setChainActive(String chain, bool active) async {
    if (chain == 'dnac') return; // DNAC always active
    final newChains = Set<String>.from(state.activeChains);
    if (active) {
      newChains.add(chain);
    } else {
      newChains.remove(chain);
    }
    final prefs = await SharedPreferences.getInstance();
    await prefs.setStringList(_kActiveChains, newChains.toList());
    state = state.copyWith(activeChains: newChains);
  }
}

/// Provider for wallet display settings
final walletSettingsProvider =
    StateNotifierProvider<WalletSettingsNotifier, WalletSettingsState>(
  (ref) => WalletSettingsNotifier(),
);
