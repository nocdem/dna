// Wallet Settings Provider - Wallet display preferences
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

const _kHideZeroBalances = 'wallet_hide_zero_balances';
const _kHideBalances = 'wallet_hide_balances';

/// State for wallet display settings
class WalletSettingsState {
  final bool hideZeroBalances;
  final bool hideBalances;

  const WalletSettingsState({
    this.hideZeroBalances = false,
    this.hideBalances = false,
  });

  WalletSettingsState copyWith({
    bool? hideZeroBalances,
    bool? hideBalances,
  }) => WalletSettingsState(
        hideZeroBalances: hideZeroBalances ?? this.hideZeroBalances,
        hideBalances: hideBalances ?? this.hideBalances,
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
}

/// Provider for wallet display settings
final walletSettingsProvider =
    StateNotifierProvider<WalletSettingsNotifier, WalletSettingsState>(
  (ref) => WalletSettingsNotifier(),
);
