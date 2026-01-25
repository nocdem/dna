// Wallet Settings Provider - Wallet display preferences
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

const _kHideZeroBalances = 'wallet_hide_zero_balances';

/// State for wallet display settings
class WalletSettingsState {
  final bool hideZeroBalances;

  const WalletSettingsState({this.hideZeroBalances = false});

  WalletSettingsState copyWith({bool? hideZeroBalances}) => WalletSettingsState(
        hideZeroBalances: hideZeroBalances ?? this.hideZeroBalances,
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
    );
  }

  Future<void> setHideZeroBalances(bool value) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool(_kHideZeroBalances, value);
    state = state.copyWith(hideZeroBalances: value);
  }
}

/// Provider for wallet display settings
final walletSettingsProvider =
    StateNotifierProvider<WalletSettingsNotifier, WalletSettingsState>(
  (ref) => WalletSettingsNotifier(),
);
