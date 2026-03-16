// Wallet Settings Provider - Wallet display preferences
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

const _kHideZeroBalances = 'wallet_hide_zero_balances';
const _kHideBalances = 'wallet_hide_balances';
const _kSlippageOverride = 'dex_slippage_override';

/// Default max slippage before swap is disabled
const double kDefaultMaxSlippage = 10.0;

/// Max slippage when override is enabled (with warning)
const double kOverrideMaxSlippage = 50.0;

/// State for wallet display settings
class WalletSettingsState {
  final bool hideZeroBalances;
  final bool hideBalances;
  final bool slippageOverride;  // Allow up to 50% slippage (with warning)

  const WalletSettingsState({
    this.hideZeroBalances = false,
    this.hideBalances = false,
    this.slippageOverride = false,
  });

  /// Current max allowed slippage
  double get maxSlippage => slippageOverride ? kOverrideMaxSlippage : kDefaultMaxSlippage;

  WalletSettingsState copyWith({
    bool? hideZeroBalances,
    bool? hideBalances,
    bool? slippageOverride,
  }) => WalletSettingsState(
        hideZeroBalances: hideZeroBalances ?? this.hideZeroBalances,
        hideBalances: hideBalances ?? this.hideBalances,
        slippageOverride: slippageOverride ?? this.slippageOverride,
      );
}

/// Notifier for wallet display settings
class WalletSettingsNotifier extends StateNotifier<WalletSettingsState> {
  WalletSettingsNotifier() : super(const WalletSettingsState()) {
    _load();
  }

  Future<void> _load() async {
    final prefs = await SharedPreferences.getInstance();
    state = WalletSettingsState(
      hideZeroBalances: prefs.getBool(_kHideZeroBalances) ?? false,
      hideBalances: prefs.getBool(_kHideBalances) ?? false,
      slippageOverride: prefs.getBool(_kSlippageOverride) ?? false,
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

  Future<void> toggleSlippageOverride() async {
    final prefs = await SharedPreferences.getInstance();
    final newValue = !state.slippageOverride;
    await prefs.setBool(_kSlippageOverride, newValue);
    state = state.copyWith(slippageOverride: newValue);
  }
}

/// Provider for wallet display settings
final walletSettingsProvider =
    StateNotifierProvider<WalletSettingsNotifier, WalletSettingsState>(
  (ref) => WalletSettingsNotifier(),
);
