// Theme Provider - App theme state
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../theme/dna_theme.dart';

/// Theme data provider - single cpunk.io theme
final themeDataProvider = Provider<ThemeData>((ref) => DnaTheme.theme);
