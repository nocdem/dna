// Theme Provider - App theme state
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../theme/dna_theme.dart';

/// Current theme provider
final themeProvider = StateNotifierProvider<ThemeNotifier, AppTheme>(
  (ref) => ThemeNotifier(),
);

class ThemeNotifier extends StateNotifier<AppTheme> {
  ThemeNotifier() : super(AppTheme.dna) {
    _loadTheme();
  }

  Future<void> _loadTheme() async {
    final prefs = await SharedPreferences.getInstance();
    final themeName = prefs.getString('theme') ?? 'dna';
    state = themeName == 'club' ? AppTheme.club : AppTheme.dna;
  }

  Future<void> setTheme(AppTheme theme) async {
    state = theme;
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('theme', theme == AppTheme.club ? 'club' : 'dna');
  }

  void toggleTheme() {
    setTheme(state == AppTheme.dna ? AppTheme.club : AppTheme.dna);
  }
}
