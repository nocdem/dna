# UI Redesign Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Redesign DNA Connect's Flutter UI from cpunk-neon drawer navigation to a Trust Wallet-style bottom tab interface with cyan-to-blue gradient, card-based layouts, dark+light themes, and a formal component library.

**Architecture:** Design System First approach. Build a modular `lib/design_system/` component library with theme tokens, reusable widgets, and barrel exports. Then migrate each screen to use the new components. Navigation changes from drawer to bottom tabs (Chats, Groups, Feed, More). Existing Riverpod providers and FFI bindings remain untouched.

**Tech Stack:** Flutter 3.x, Riverpod 2.6.1, Font Awesome icons, Dart FFI

**Design Doc:** `docs/plans/2026-02-23-ui-redesign-design.md`

---

## Phase 1: Theme Foundation

### Task 1: Create color tokens (dark + light)

**Files:**
- Create: `lib/design_system/theme/dna_colors.dart`

**Step 1: Create the color tokens file**

```dart
import 'package:flutter/material.dart';

/// DNA Connect color system
/// Supports both dark and light themes with consistent brand identity
class DnaColors {
  DnaColors._();

  // ─── Brand Gradient ───────────────────────────────────────────
  static const gradientStart = Color(0xFF00D4FF); // Cyan
  static const gradientEnd = Color(0xFF0066FF);   // Blue
  static const primaryFixed = Color(0xFF0066FF);  // Solid fallback

  // ─── Dark Theme ───────────────────────────────────────────────
  static const darkBackground = Color(0xFF0A0E1A);
  static const darkSurface = Color(0xFF131829);
  static const darkSurfaceVariant = Color(0xFF1A2035);
  static const darkText = Color(0xFFF0F2FA);
  static const darkTextSecondary = Color(0xFF8B95B8);
  static const darkDivider = Color(0x0FFFFFFF);      // 6% white
  static const darkDividerAccent = Color(0x4D00D4FF); // 30% cyan

  // ─── Light Theme ──────────────────────────────────────────────
  static const lightBackground = Color(0xFFF5F7FA);
  static const lightSurface = Color(0xFFFFFFFF);
  static const lightSurfaceVariant = Color(0xFFEEF1F6);
  static const lightText = Color(0xFF0F172A);
  static const lightTextSecondary = Color(0xFF64748B);
  static const lightDivider = Color(0x0F000000);      // 6% black
  static const lightDividerAccent = Color(0x4D0066FF); // 30% blue

  // ─── Semantic (shared across themes) ──────────────────────────
  static const success = Color(0xFF34D399);
  static const error = Color(0xFFEF4444);
  static const warning = Color(0xFFF59E0B);
  static const info = Color(0xFF3B82F6);
  static const offline = Color(0xFF6B7280);

  // ─── Snackbar backgrounds ─────────────────────────────────────
  static const snackbarSuccessDark = Color(0xFF0D3320);
  static const snackbarErrorDark = Color(0xFF3D1A1A);
  static const snackbarInfoDark = Color(0xFF1A2744);
  static const snackbarSuccessLight = Color(0xFFD1FAE5);
  static const snackbarErrorLight = Color(0xFFFEE2E2);
  static const snackbarInfoLight = Color(0xFFDBEAFE);
}
```

**Step 2: Verify build**

Run: `cd /opt/dna-messenger/dna_messenger_flutter && flutter analyze lib/design_system/theme/dna_colors.dart`
Expected: No errors

**Step 3: Commit**

```bash
git add lib/design_system/theme/dna_colors.dart
git commit -m "feat(ui): add color token system with dark+light support"
```

---

### Task 2: Create gradient definitions

**Files:**
- Create: `lib/design_system/theme/dna_gradients.dart`

**Step 1: Create the gradients file**

```dart
import 'package:flutter/material.dart';
import 'dna_colors.dart';

/// Reusable gradient definitions for the DNA design system
class DnaGradients {
  DnaGradients._();

  /// Primary brand gradient (cyan → blue) — horizontal
  static const primary = LinearGradient(
    colors: [DnaColors.gradientStart, DnaColors.gradientEnd],
  );

  /// Primary gradient — vertical (for headers, cards)
  static const primaryVertical = LinearGradient(
    begin: Alignment.topCenter,
    end: Alignment.bottomCenter,
    colors: [DnaColors.gradientStart, DnaColors.gradientEnd],
  );

  /// Subtle gradient for backgrounds (very low opacity)
  static LinearGradient primarySoft(Brightness brightness) {
    final opacity = brightness == Brightness.dark ? 0.08 : 0.05;
    return LinearGradient(
      colors: [
        DnaColors.gradientStart.withValues(alpha: opacity),
        DnaColors.gradientEnd.withValues(alpha: opacity),
      ],
    );
  }

  /// Shader callback for gradient text/icons
  static Shader primaryShader(Rect bounds) {
    return primary.createShader(bounds);
  }
}
```

**Step 2: Verify build**

Run: `cd /opt/dna-messenger/dna_messenger_flutter && flutter analyze lib/design_system/theme/dna_gradients.dart`

**Step 3: Commit**

```bash
git add lib/design_system/theme/dna_gradients.dart
git commit -m "feat(ui): add gradient definitions"
```

---

### Task 3: Create typography system

**Files:**
- Create: `lib/design_system/theme/dna_typography.dart`

**Step 1: Create the typography file**

```dart
import 'package:flutter/material.dart';

/// Typography scale for DNA Connect
/// Based on Material 3 type scale with custom weights
class DnaTypography {
  DnaTypography._();

  static TextTheme textTheme(Color textColor, Color mutedColor) {
    return TextTheme(
      // Display
      displayLarge: TextStyle(fontSize: 32, fontWeight: FontWeight.w700, color: textColor, height: 1.2),
      displayMedium: TextStyle(fontSize: 28, fontWeight: FontWeight.w700, color: textColor, height: 1.2),
      displaySmall: TextStyle(fontSize: 24, fontWeight: FontWeight.w700, color: textColor, height: 1.3),

      // Headlines
      headlineLarge: TextStyle(fontSize: 22, fontWeight: FontWeight.w700, color: textColor, height: 1.3),
      headlineMedium: TextStyle(fontSize: 20, fontWeight: FontWeight.w600, color: textColor, height: 1.3),
      headlineSmall: TextStyle(fontSize: 18, fontWeight: FontWeight.w600, color: textColor, height: 1.4),

      // Titles
      titleLarge: TextStyle(fontSize: 17, fontWeight: FontWeight.w600, color: textColor, height: 1.4),
      titleMedium: TextStyle(fontSize: 15, fontWeight: FontWeight.w600, color: textColor, height: 1.4),
      titleSmall: TextStyle(fontSize: 13, fontWeight: FontWeight.w600, color: textColor, height: 1.4),

      // Body
      bodyLarge: TextStyle(fontSize: 16, fontWeight: FontWeight.w400, color: textColor, height: 1.5),
      bodyMedium: TextStyle(fontSize: 14, fontWeight: FontWeight.w400, color: textColor, height: 1.5),
      bodySmall: TextStyle(fontSize: 12, fontWeight: FontWeight.w400, color: mutedColor, height: 1.5),

      // Labels
      labelLarge: TextStyle(fontSize: 14, fontWeight: FontWeight.w500, color: textColor, height: 1.4),
      labelMedium: TextStyle(fontSize: 12, fontWeight: FontWeight.w500, color: textColor, height: 1.4),
      labelSmall: TextStyle(fontSize: 11, fontWeight: FontWeight.w500, color: mutedColor, height: 1.4, letterSpacing: 0.5),
    );
  }
}
```

**Step 2: Verify build, commit**

```bash
git add lib/design_system/theme/dna_typography.dart
git commit -m "feat(ui): add typography scale"
```

---

### Task 4: Create spacing constants

**Files:**
- Create: `lib/design_system/theme/dna_spacing.dart`

**Step 1: Create the spacing file**

```dart
/// Spacing and sizing constants for consistent layouts
/// Based on 4px grid system
class DnaSpacing {
  DnaSpacing._();

  // Base spacing (4px grid)
  static const double xs = 4;
  static const double sm = 8;
  static const double md = 12;
  static const double lg = 16;
  static const double xl = 24;
  static const double xxl = 32;
  static const double xxxl = 48;

  // Border radius
  static const double radiusSm = 8;
  static const double radiusMd = 12;
  static const double radiusLg = 16;
  static const double radiusXl = 24;
  static const double radiusFull = 999;

  // Avatar sizes
  static const double avatarSm = 32;
  static const double avatarMd = 40;
  static const double avatarLg = 56;
  static const double avatarXl = 80;

  // Icon sizes
  static const double iconSm = 16;
  static const double iconMd = 20;
  static const double iconLg = 24;

  // Bottom bar
  static const double bottomBarHeight = 64;

  // Card elevation
  static const double elevationNone = 0;
  static const double elevationLow = 2;
  static const double elevationMed = 4;
  static const double elevationHigh = 8;
}
```

**Step 2: Verify build, commit**

```bash
git add lib/design_system/theme/dna_spacing.dart
git commit -m "feat(ui): add spacing constants"
```

---

### Task 5: Create ThemeData builders (dark + light) and theme provider

**Files:**
- Create: `lib/design_system/theme/dna_theme.dart` (NEW — replaces old theme)
- Modify: `lib/providers/theme_provider.dart` (currently 1-line provider)
- Modify: `lib/main.dart` (wire up theme switching)

**Step 1: Create the new theme builder**

This file builds complete `ThemeData` for both dark and light modes using the token files above.

```dart
import 'package:flutter/material.dart';
import 'dna_colors.dart';
import 'dna_typography.dart';
import 'dna_spacing.dart';

/// Builds ThemeData for dark and light modes
class DnaTheme {
  DnaTheme._();

  static ThemeData dark() => _build(Brightness.dark);
  static ThemeData light() => _build(Brightness.light);

  static ThemeData _build(Brightness brightness) {
    final isDark = brightness == Brightness.dark;

    final bg = isDark ? DnaColors.darkBackground : DnaColors.lightBackground;
    final surface = isDark ? DnaColors.darkSurface : DnaColors.lightSurface;
    final surfaceVariant = isDark ? DnaColors.darkSurfaceVariant : DnaColors.lightSurfaceVariant;
    final text = isDark ? DnaColors.darkText : DnaColors.lightText;
    final textSecondary = isDark ? DnaColors.darkTextSecondary : DnaColors.lightTextSecondary;
    final divider = isDark ? DnaColors.darkDivider : DnaColors.lightDivider;
    final dividerAccent = isDark ? DnaColors.darkDividerAccent : DnaColors.lightDividerAccent;

    return ThemeData(
      useMaterial3: true,
      brightness: brightness,
      scaffoldBackgroundColor: bg,
      colorScheme: ColorScheme(
        brightness: brightness,
        primary: DnaColors.primaryFixed,
        onPrimary: Colors.white,
        secondary: DnaColors.gradientStart,
        onSecondary: isDark ? DnaColors.darkBackground : Colors.white,
        error: DnaColors.error,
        onError: Colors.white,
        surface: surface,
        onSurface: text,
        surfaceContainerHighest: surfaceVariant,
        outline: dividerAccent,
        outlineVariant: divider,
      ),
      appBarTheme: AppBarTheme(
        backgroundColor: bg,
        foregroundColor: text,
        elevation: 0,
        scrolledUnderElevation: 0,
        centerTitle: false,
        titleTextStyle: TextStyle(
          color: text,
          fontSize: 20,
          fontWeight: FontWeight.w600,
        ),
      ),
      cardTheme: CardThemeData(
        color: surface,
        elevation: DnaSpacing.elevationLow,
        shadowColor: isDark ? Colors.black54 : Colors.black12,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(DnaSpacing.radiusMd),
        ),
      ),
      listTileTheme: ListTileThemeData(
        textColor: text,
        iconColor: DnaColors.primaryFixed,
        contentPadding: const EdgeInsets.symmetric(
          horizontal: DnaSpacing.lg,
          vertical: DnaSpacing.xs,
        ),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: surfaceVariant,
        hintStyle: TextStyle(color: textSecondary),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(DnaSpacing.radiusSm),
          borderSide: BorderSide.none,
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(DnaSpacing.radiusSm),
          borderSide: BorderSide.none,
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(DnaSpacing.radiusSm),
          borderSide: const BorderSide(color: DnaColors.primaryFixed, width: 2),
        ),
        contentPadding: const EdgeInsets.symmetric(
          horizontal: DnaSpacing.lg,
          vertical: DnaSpacing.md,
        ),
      ),
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: DnaColors.primaryFixed,
          foregroundColor: Colors.white,
          elevation: DnaSpacing.elevationLow,
          shadowColor: DnaColors.primaryFixed.withValues(alpha: 0.3),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(DnaSpacing.radiusSm),
          ),
          padding: const EdgeInsets.symmetric(
            horizontal: DnaSpacing.xl,
            vertical: DnaSpacing.md,
          ),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          foregroundColor: DnaColors.primaryFixed,
          side: const BorderSide(color: DnaColors.primaryFixed),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(DnaSpacing.radiusSm),
          ),
          padding: const EdgeInsets.symmetric(
            horizontal: DnaSpacing.xl,
            vertical: DnaSpacing.md,
          ),
        ),
      ),
      textButtonTheme: TextButtonThemeData(
        style: TextButton.styleFrom(
          foregroundColor: DnaColors.primaryFixed,
        ),
      ),
      floatingActionButtonTheme: FloatingActionButtonThemeData(
        backgroundColor: DnaColors.primaryFixed,
        foregroundColor: Colors.white,
        elevation: DnaSpacing.elevationMed,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(DnaSpacing.radiusLg),
        ),
      ),
      dividerTheme: DividerThemeData(
        color: divider,
        thickness: 1,
      ),
      textTheme: DnaTypography.textTheme(text, textSecondary),
      iconTheme: IconThemeData(color: text, size: DnaSpacing.iconLg),
      snackBarTheme: SnackBarThemeData(
        backgroundColor: surface,
        contentTextStyle: TextStyle(color: text),
        actionTextColor: DnaColors.primaryFixed,
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(DnaSpacing.radiusSm),
        ),
        insetPadding: const EdgeInsets.only(left: 16, right: 16, bottom: 120),
      ),
      switchTheme: SwitchThemeData(
        thumbColor: WidgetStateProperty.resolveWith((states) {
          if (states.contains(WidgetState.selected)) return Colors.white;
          return textSecondary;
        }),
        trackColor: WidgetStateProperty.resolveWith((states) {
          if (states.contains(WidgetState.selected)) return DnaColors.primaryFixed;
          return surfaceVariant;
        }),
      ),
      dialogTheme: DialogThemeData(
        backgroundColor: surface,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(DnaSpacing.radiusLg),
        ),
        elevation: DnaSpacing.elevationHigh,
      ),
      bottomNavigationBarTheme: BottomNavigationBarThemeData(
        backgroundColor: surface,
        selectedItemColor: DnaColors.primaryFixed,
        unselectedItemColor: textSecondary,
        elevation: DnaSpacing.elevationMed,
        type: BottomNavigationBarType.fixed,
      ),
      textSelectionTheme: TextSelectionThemeData(
        selectionColor: DnaColors.primaryFixed.withValues(alpha: 0.3),
        cursorColor: DnaColors.primaryFixed,
        selectionHandleColor: DnaColors.primaryFixed,
      ),
    );
  }
}
```

**Step 2: Update theme provider**

File: `lib/providers/theme_provider.dart`

Replace the current single-line provider with a reactive theme mode provider:

```dart
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Theme mode state — persists to shared preferences
final themeModeProvider = StateNotifierProvider<ThemeModeNotifier, ThemeMode>((ref) {
  return ThemeModeNotifier();
});

class ThemeModeNotifier extends StateNotifier<ThemeMode> {
  static const _key = 'theme_mode';

  ThemeModeNotifier() : super(ThemeMode.dark) {
    _load();
  }

  Future<void> _load() async {
    final prefs = await SharedPreferences.getInstance();
    final value = prefs.getString(_key);
    if (value == 'light') {
      state = ThemeMode.light;
    } else if (value == 'system') {
      state = ThemeMode.system;
    } else {
      state = ThemeMode.dark;
    }
  }

  Future<void> setThemeMode(ThemeMode mode) async {
    state = mode;
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_key, mode.name);
  }

  Future<void> toggle() async {
    final next = state == ThemeMode.dark ? ThemeMode.light : ThemeMode.dark;
    await setThemeMode(next);
  }
}
```

**Step 3: Update main.dart to use theme switching**

In `lib/main.dart`, update the `DnaMessengerApp` widget:

Find:
```dart
import 'theme/dna_theme.dart';
```
Replace with:
```dart
import 'design_system/theme/dna_theme.dart';
```

Find the MaterialApp in `DnaMessengerApp.build()`:
```dart
    return MaterialApp(
      title: 'DNA Connect',
      debugShowCheckedModeBanner: false,
      theme: DnaTheme.theme,
      navigatorObservers: [routeObserver],
      home: const _AppLoader(),
    );
```
Replace with:
```dart
    final themeMode = ref.watch(themeModeProvider);
    return MaterialApp(
      title: 'DNA Connect',
      debugShowCheckedModeBanner: false,
      theme: DnaTheme.light(),
      darkTheme: DnaTheme.dark(),
      themeMode: themeMode,
      navigatorObservers: [routeObserver],
      home: const _AppLoader(),
    );
```

**Step 4: Update all imports across the codebase**

Every file that currently imports the old theme needs updating:

Search for: `import '../theme/dna_theme.dart'` and `import '../../theme/dna_theme.dart'`

These files reference `DnaColors` directly and need to import from the new location:
```dart
import 'package:dna_messenger/design_system/theme/dna_colors.dart';
```

**Important:** Do NOT delete `lib/theme/dna_theme.dart` yet. Instead, make it re-export the new files for backward compatibility during migration:

```dart
// Legacy re-export — will be removed after full migration
export '../design_system/theme/dna_colors.dart';
export '../design_system/theme/dna_theme.dart' hide DnaTheme;
// Keep old DnaTheme.theme getter working during migration
import '../design_system/theme/dna_theme.dart' as new_theme;
class DnaTheme {
  static get theme => new_theme.DnaTheme.dark();
}
```

Actually — simpler approach: keep the old file as a pure re-export shim so nothing breaks during migration. Each screen migration task will update its own imports.

**Step 5: Verify build**

Run: `cd /opt/dna-messenger/dna_messenger_flutter && flutter build linux`
Expected: Build succeeds with no errors

**Step 6: Commit**

```bash
git add lib/design_system/theme/dna_theme.dart lib/providers/theme_provider.dart lib/main.dart lib/theme/dna_theme.dart
git commit -m "feat(ui): add dark+light theme system with persistent toggle"
```

---

## Phase 2: Core Components

### Task 6: Create DnaCard component

**Files:**
- Create: `lib/design_system/components/dna_card.dart`

**Step 1: Create the component**

```dart
import 'package:flutter/material.dart';
import '../theme/dna_spacing.dart';
import '../theme/dna_gradients.dart';

/// A themed card with optional gradient header and elevation levels
class DnaCard extends StatelessWidget {
  final Widget child;
  final EdgeInsetsGeometry? padding;
  final EdgeInsetsGeometry? margin;
  final double? elevation;
  final bool gradientHeader;
  final VoidCallback? onTap;
  final BorderRadiusGeometry? borderRadius;

  const DnaCard({
    super.key,
    required this.child,
    this.padding,
    this.margin,
    this.elevation,
    this.gradientHeader = false,
    this.onTap,
    this.borderRadius,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final radius = borderRadius ?? BorderRadius.circular(DnaSpacing.radiusMd);

    Widget card = Material(
      color: theme.cardTheme.color ?? theme.colorScheme.surface,
      elevation: elevation ?? DnaSpacing.elevationLow,
      shadowColor: theme.cardTheme.shadowColor,
      borderRadius: radius,
      clipBehavior: Clip.antiAlias,
      child: InkWell(
        onTap: onTap,
        borderRadius: radius as BorderRadius?,
        child: Padding(
          padding: padding ?? const EdgeInsets.all(DnaSpacing.lg),
          child: child,
        ),
      ),
    );

    if (gradientHeader) {
      card = Container(
        decoration: BoxDecoration(
          borderRadius: radius,
          gradient: DnaGradients.primaryVertical,
        ),
        child: card,
      );
    }

    if (margin != null) {
      card = Padding(padding: margin!, child: card);
    }

    return card;
  }
}
```

**Step 2: Verify build, commit**

```bash
git add lib/design_system/components/dna_card.dart
git commit -m "feat(ui): add DnaCard component"
```

---

### Task 7: Create DnaButton component

**Files:**
- Create: `lib/design_system/components/dna_button.dart`

**Step 1: Create the component**

```dart
import 'package:flutter/material.dart';
import '../theme/dna_colors.dart';
import '../theme/dna_gradients.dart';
import '../theme/dna_spacing.dart';

enum DnaButtonVariant { primary, secondary, ghost }

/// Themed button with gradient primary variant and loading state
class DnaButton extends StatelessWidget {
  final String label;
  final VoidCallback? onPressed;
  final DnaButtonVariant variant;
  final bool loading;
  final IconData? icon;
  final bool expand;

  const DnaButton({
    super.key,
    required this.label,
    this.onPressed,
    this.variant = DnaButtonVariant.primary,
    this.loading = false,
    this.icon,
    this.expand = false,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    Widget child = Row(
      mainAxisSize: expand ? MainAxisSize.max : MainAxisSize.min,
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        if (loading) ...[
          SizedBox(
            width: 18,
            height: 18,
            child: CircularProgressIndicator(
              strokeWidth: 2,
              color: variant == DnaButtonVariant.primary
                  ? Colors.white
                  : DnaColors.primaryFixed,
            ),
          ),
          const SizedBox(width: DnaSpacing.sm),
        ] else if (icon != null) ...[
          Icon(icon, size: DnaSpacing.iconMd),
          const SizedBox(width: DnaSpacing.sm),
        ],
        Text(label),
      ],
    );

    final disabled = onPressed == null || loading;

    switch (variant) {
      case DnaButtonVariant.primary:
        return _GradientButton(
          onPressed: disabled ? null : onPressed,
          expand: expand,
          child: child,
        );
      case DnaButtonVariant.secondary:
        return OutlinedButton(
          onPressed: disabled ? null : onPressed,
          child: child,
        );
      case DnaButtonVariant.ghost:
        return TextButton(
          onPressed: disabled ? null : onPressed,
          child: child,
        );
    }
  }
}

class _GradientButton extends StatelessWidget {
  final VoidCallback? onPressed;
  final bool expand;
  final Widget child;

  const _GradientButton({
    this.onPressed,
    this.expand = false,
    required this.child,
  });

  @override
  Widget build(BuildContext context) {
    final disabled = onPressed == null;
    return Container(
      width: expand ? double.infinity : null,
      decoration: BoxDecoration(
        gradient: disabled ? null : DnaGradients.primary,
        color: disabled ? DnaColors.offline : null,
        borderRadius: BorderRadius.circular(DnaSpacing.radiusSm),
        boxShadow: disabled
            ? null
            : [
                BoxShadow(
                  color: DnaColors.primaryFixed.withValues(alpha: 0.3),
                  blurRadius: 8,
                  offset: const Offset(0, 2),
                ),
              ],
      ),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          onTap: onPressed,
          borderRadius: BorderRadius.circular(DnaSpacing.radiusSm),
          child: Padding(
            padding: const EdgeInsets.symmetric(
              horizontal: DnaSpacing.xl,
              vertical: DnaSpacing.md,
            ),
            child: DefaultTextStyle(
              style: const TextStyle(
                color: Colors.white,
                fontWeight: FontWeight.w600,
                fontSize: 15,
              ),
              child: IconTheme(
                data: const IconThemeData(color: Colors.white),
                child: child,
              ),
            ),
          ),
        ),
      ),
    );
  }
}
```

**Step 2: Verify build, commit**

```bash
git add lib/design_system/components/dna_button.dart
git commit -m "feat(ui): add DnaButton with gradient primary variant"
```

---

### Task 8: Create DnaAvatar component

**Files:**
- Create: `lib/design_system/components/dna_avatar.dart`

**Step 1: Create the component**

```dart
import 'dart:typed_data';
import 'package:flutter/material.dart';
import '../theme/dna_colors.dart';
import '../theme/dna_spacing.dart';

enum DnaAvatarSize { sm, md, lg, xl }

/// Avatar with image, initials fallback, and online status dot
class DnaAvatar extends StatelessWidget {
  final Uint8List? imageBytes;
  final String? name;
  final DnaAvatarSize size;
  final bool showOnlineStatus;
  final bool isOnline;

  const DnaAvatar({
    super.key,
    this.imageBytes,
    this.name,
    this.size = DnaAvatarSize.md,
    this.showOnlineStatus = false,
    this.isOnline = false,
  });

  double get _radius => switch (size) {
    DnaAvatarSize.sm => DnaSpacing.avatarSm / 2,
    DnaAvatarSize.md => DnaSpacing.avatarMd / 2,
    DnaAvatarSize.lg => DnaSpacing.avatarLg / 2,
    DnaAvatarSize.xl => DnaSpacing.avatarXl / 2,
  };

  double get _fontSize => switch (size) {
    DnaAvatarSize.sm => 12,
    DnaAvatarSize.md => 16,
    DnaAvatarSize.lg => 22,
    DnaAvatarSize.xl => 30,
  };

  String _getInitials(String? name) {
    if (name == null || name.isEmpty) return '?';
    final words = name.split(' ').where((w) => w.isNotEmpty).toList();
    if (words.isEmpty) return '?';
    if (words.length >= 2) {
      return '${words[0][0]}${words[1][0]}'.toUpperCase();
    }
    return words[0].substring(0, words[0].length.clamp(0, 2)).toUpperCase();
  }

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;

    Widget avatar;
    if (imageBytes != null) {
      avatar = CircleAvatar(
        radius: _radius,
        backgroundImage: MemoryImage(imageBytes!),
      );
    } else {
      avatar = CircleAvatar(
        radius: _radius,
        backgroundColor: isDark
            ? DnaColors.primaryFixed.withValues(alpha: 0.15)
            : DnaColors.primaryFixed.withValues(alpha: 0.1),
        child: Text(
          _getInitials(name),
          style: TextStyle(
            fontSize: _fontSize,
            fontWeight: FontWeight.w600,
            color: DnaColors.primaryFixed,
          ),
        ),
      );
    }

    if (!showOnlineStatus) return avatar;

    final dotSize = _radius * 0.4;
    return Stack(
      children: [
        avatar,
        Positioned(
          right: 0,
          bottom: 0,
          child: Container(
            width: dotSize,
            height: dotSize,
            decoration: BoxDecoration(
              color: isOnline ? DnaColors.success : DnaColors.offline,
              shape: BoxShape.circle,
              border: Border.all(
                color: Theme.of(context).scaffoldBackgroundColor,
                width: 2,
              ),
              boxShadow: isOnline
                  ? [
                      BoxShadow(
                        color: DnaColors.success.withValues(alpha: 0.4),
                        blurRadius: 4,
                      ),
                    ]
                  : null,
            ),
          ),
        ),
      ],
    );
  }
}
```

**Step 2: Verify build, commit**

```bash
git add lib/design_system/components/dna_avatar.dart
git commit -m "feat(ui): add DnaAvatar with online status dot"
```

---

### Task 9: Create DnaListTile component

**Files:**
- Create: `lib/design_system/components/dna_list_tile.dart`

**Step 1: Create the component**

```dart
import 'package:flutter/material.dart';
import '../theme/dna_spacing.dart';

/// Themed list tile for chats, contacts, settings rows
class DnaListTile extends StatelessWidget {
  final Widget? leading;
  final String title;
  final String? subtitle;
  final Widget? trailing;
  final VoidCallback? onTap;
  final VoidCallback? onLongPress;
  final EdgeInsetsGeometry? padding;
  final bool dense;

  const DnaListTile({
    super.key,
    this.leading,
    required this.title,
    this.subtitle,
    this.trailing,
    this.onTap,
    this.onLongPress,
    this.padding,
    this.dense = false,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return InkWell(
      onTap: onTap,
      onLongPress: onLongPress,
      child: Padding(
        padding: padding ?? EdgeInsets.symmetric(
          horizontal: DnaSpacing.lg,
          vertical: dense ? DnaSpacing.sm : DnaSpacing.md,
        ),
        child: Row(
          children: [
            if (leading != null) ...[
              leading!,
              const SizedBox(width: DnaSpacing.md),
            ],
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(
                    title,
                    style: theme.textTheme.titleMedium,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                  if (subtitle != null) ...[
                    const SizedBox(height: 2),
                    Text(
                      subtitle!,
                      style: theme.textTheme.bodySmall,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ],
                ],
              ),
            ),
            if (trailing != null) ...[
              const SizedBox(width: DnaSpacing.sm),
              trailing!,
            ],
          ],
        ),
      ),
    );
  }
}
```

**Step 2: Verify build, commit**

```bash
git add lib/design_system/components/dna_list_tile.dart
git commit -m "feat(ui): add DnaListTile component"
```

---

### Task 10: Create DnaBadge component

**Files:**
- Create: `lib/design_system/components/dna_badge.dart`

**Step 1: Create the component**

```dart
import 'package:flutter/material.dart';
import '../theme/dna_colors.dart';

/// Notification count badge — overlay on icons/avatars
class DnaBadge extends StatelessWidget {
  final int count;
  final Widget child;

  const DnaBadge({
    super.key,
    required this.count,
    required this.child,
  });

  @override
  Widget build(BuildContext context) {
    if (count <= 0) return child;

    return Stack(
      clipBehavior: Clip.none,
      children: [
        child,
        Positioned(
          right: -6,
          top: -4,
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 2),
            decoration: BoxDecoration(
              color: DnaColors.error,
              borderRadius: BorderRadius.circular(10),
              boxShadow: [
                BoxShadow(
                  color: DnaColors.error.withValues(alpha: 0.4),
                  blurRadius: 4,
                ),
              ],
            ),
            constraints: const BoxConstraints(minWidth: 18, minHeight: 16),
            child: Text(
              count > 99 ? '99+' : count.toString(),
              style: const TextStyle(
                color: Colors.white,
                fontSize: 10,
                fontWeight: FontWeight.w700,
              ),
              textAlign: TextAlign.center,
            ),
          ),
        ),
      ],
    );
  }
}
```

**Step 2: Verify build, commit**

```bash
git add lib/design_system/components/dna_badge.dart
git commit -m "feat(ui): add DnaBadge component"
```

---

### Task 11: Create DnaChip, DnaIconButton, DnaBottomSheet, DnaSkeleton, DnaSnackBar

**Files:**
- Create: `lib/design_system/components/dna_chip.dart`
- Create: `lib/design_system/components/dna_icon_button.dart`
- Create: `lib/design_system/components/dna_bottom_sheet.dart`
- Create: `lib/design_system/components/dna_skeleton.dart`
- Create: `lib/design_system/components/dna_snack_bar.dart`

These are smaller components. Implement each following the same pattern as above:

**DnaChip** — Filter/tag chip with gradient selected state:
- Props: `label`, `selected`, `onTap`, `count`
- Selected state: gradient background, white text
- Unselected: surface background, muted text

**DnaIconButton** — Circular icon button:
- Props: `icon`, `onPressed`, `variant` (solid/outlined/ghost), `size`
- Solid: gradient background
- Outlined: border with primary color
- Ghost: transparent, just the icon

**DnaBottomSheet** — Modal sheet helper:
- Static `show()` method that wraps `showModalBottomSheet`
- Rounded top corners, drag handle, proper theming

**DnaSkeleton** — Loading shimmer placeholder:
- Props: `width`, `height`, `borderRadius`
- Animated shimmer effect using `AnimationController`
- Uses surface/surfaceVariant colors for the shimmer

**DnaSnackBar** — Themed toast helper:
- Static methods: `success()`, `error()`, `info()`
- Uses semantic colors from DnaColors
- Calls `ScaffoldMessenger.of(context).showSnackBar()`

**After creating all 5 files, verify build and commit:**

```bash
git add lib/design_system/components/
git commit -m "feat(ui): add DnaChip, DnaIconButton, DnaBottomSheet, DnaSkeleton, DnaSnackBar"
```

---

## Phase 3: Navigation Components

### Task 12: Create DnaBottomBar component

**Files:**
- Create: `lib/design_system/navigation/dna_bottom_bar.dart`

**Step 1: Create the component**

```dart
import 'package:flutter/material.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../theme/dna_colors.dart';
import '../theme/dna_gradients.dart';
import '../theme/dna_spacing.dart';
import '../components/dna_badge.dart';

class DnaBottomBarItem {
  final IconData icon;
  final IconData activeIcon;
  final String label;
  final int badgeCount;

  const DnaBottomBarItem({
    required this.icon,
    required this.activeIcon,
    required this.label,
    this.badgeCount = 0,
  });
}

/// Bottom navigation bar with gradient active state and badge support
class DnaBottomBar extends StatelessWidget {
  final int currentIndex;
  final ValueChanged<int> onTap;
  final List<DnaBottomBarItem> items;

  const DnaBottomBar({
    super.key,
    required this.currentIndex,
    required this.onTap,
    required this.items,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isDark = theme.brightness == Brightness.dark;
    final surface = isDark ? DnaColors.darkSurface : DnaColors.lightSurface;
    final muted = isDark ? DnaColors.darkTextSecondary : DnaColors.lightTextSecondary;

    return Container(
      height: DnaSpacing.bottomBarHeight + MediaQuery.of(context).padding.bottom,
      decoration: BoxDecoration(
        color: surface,
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: isDark ? 0.3 : 0.08),
            blurRadius: 8,
            offset: const Offset(0, -2),
          ),
        ],
      ),
      child: SafeArea(
        top: false,
        child: Row(
          children: List.generate(items.length, (i) {
            final item = items[i];
            final isActive = i == currentIndex;
            return Expanded(
              child: _BottomBarTab(
                item: item,
                isActive: isActive,
                mutedColor: muted,
                onTap: () => onTap(i),
              ),
            );
          }),
        ),
      ),
    );
  }
}

class _BottomBarTab extends StatelessWidget {
  final DnaBottomBarItem item;
  final bool isActive;
  final Color mutedColor;
  final VoidCallback onTap;

  const _BottomBarTab({
    required this.item,
    required this.isActive,
    required this.mutedColor,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final icon = FaIcon(
      isActive ? item.activeIcon : item.icon,
      size: DnaSpacing.iconMd,
      color: isActive ? null : mutedColor,
    );

    final gradientIcon = isActive
        ? ShaderMask(
            shaderCallback: DnaGradients.primaryShader,
            child: FaIcon(
              item.activeIcon,
              size: DnaSpacing.iconMd,
              color: Colors.white, // Gets masked by gradient
            ),
          )
        : icon;

    return InkResponse(
      onTap: onTap,
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          if (isActive)
            Container(
              width: 24,
              height: 2,
              margin: const EdgeInsets.only(bottom: DnaSpacing.xs),
              decoration: BoxDecoration(
                gradient: DnaGradients.primary,
                borderRadius: BorderRadius.circular(1),
              ),
            )
          else
            const SizedBox(height: 2 + DnaSpacing.xs),
          item.badgeCount > 0
              ? DnaBadge(count: item.badgeCount, child: gradientIcon)
              : gradientIcon,
          const SizedBox(height: DnaSpacing.xs),
          Text(
            item.label,
            style: TextStyle(
              fontSize: 11,
              fontWeight: isActive ? FontWeight.w600 : FontWeight.w400,
              color: isActive ? DnaColors.primaryFixed : mutedColor,
            ),
          ),
        ],
      ),
    );
  }
}
```

**Step 2: Verify build, commit**

```bash
git add lib/design_system/navigation/dna_bottom_bar.dart
git commit -m "feat(ui): add DnaBottomBar with gradient active state"
```

---

### Task 13: Create DnaAppBar component

**Files:**
- Create: `lib/design_system/navigation/dna_app_bar.dart`

**Step 1: Create the component**

A custom app bar that integrates with the design system. Supports optional gradient background and integrated search.

```dart
import 'package:flutter/material.dart';
import '../theme/dna_spacing.dart';

/// Themed app bar with optional gradient and search integration
class DnaAppBar extends StatelessWidget implements PreferredSizeWidget {
  final String title;
  final List<Widget>? actions;
  final Widget? leading;
  final bool centerTitle;
  final PreferredSizeWidget? bottom;

  const DnaAppBar({
    super.key,
    required this.title,
    this.actions,
    this.leading,
    this.centerTitle = false,
    this.bottom,
  });

  @override
  Size get preferredSize => Size.fromHeight(
    kToolbarHeight + (bottom?.preferredSize.height ?? 0),
  );

  @override
  Widget build(BuildContext context) {
    return AppBar(
      title: Text(title),
      leading: leading,
      actions: actions,
      centerTitle: centerTitle,
      bottom: bottom,
    );
  }
}
```

**Step 2: Verify build, commit**

```bash
git add lib/design_system/navigation/dna_app_bar.dart
git commit -m "feat(ui): add DnaAppBar component"
```

---

### Task 14: Create DnaMoreMenu component (More tab screen)

**Files:**
- Create: `lib/design_system/navigation/dna_more_menu.dart`

**Step 1: Create the component**

This is a reusable grid+list layout for the "More" tab. It takes a list of grid items and list items.

```dart
import 'package:flutter/material.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../theme/dna_colors.dart';
import '../theme/dna_gradients.dart';
import '../theme/dna_spacing.dart';

class DnaMoreGridItem {
  final IconData icon;
  final String label;
  final VoidCallback onTap;
  final int badgeCount;

  const DnaMoreGridItem({
    required this.icon,
    required this.label,
    required this.onTap,
    this.badgeCount = 0,
  });
}

class DnaMoreListItem {
  final IconData icon;
  final String label;
  final VoidCallback onTap;
  final Widget? trailing;

  const DnaMoreListItem({
    required this.icon,
    required this.label,
    required this.onTap,
    this.trailing,
  });
}

/// Grid + list layout for the "More" tab
class DnaMoreMenu extends StatelessWidget {
  final List<DnaMoreGridItem> gridItems;
  final List<DnaMoreListItem> listItems;
  final Widget? header;

  const DnaMoreMenu({
    super.key,
    required this.gridItems,
    required this.listItems,
    this.header,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return ListView(
      padding: const EdgeInsets.all(DnaSpacing.lg),
      children: [
        if (header != null) ...[
          header!,
          const SizedBox(height: DnaSpacing.lg),
        ],
        // Grid section
        GridView.count(
          crossAxisCount: 3,
          shrinkWrap: true,
          physics: const NeverScrollableScrollPhysics(),
          mainAxisSpacing: DnaSpacing.md,
          crossAxisSpacing: DnaSpacing.md,
          children: gridItems.map((item) => _GridTile(item: item)).toList(),
        ),
        const SizedBox(height: DnaSpacing.xl),
        const Divider(),
        const SizedBox(height: DnaSpacing.sm),
        // List section
        ...listItems.map((item) => ListTile(
          leading: FaIcon(item.icon, size: DnaSpacing.iconMd, color: theme.colorScheme.onSurface),
          title: Text(item.label),
          trailing: item.trailing ?? FaIcon(
            FontAwesomeIcons.chevronRight,
            size: 14,
            color: theme.textTheme.bodySmall?.color,
          ),
          onTap: item.onTap,
        )),
      ],
    );
  }
}

class _GridTile extends StatelessWidget {
  final DnaMoreGridItem item;
  const _GridTile({required this.item});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isDark = theme.brightness == Brightness.dark;

    return Material(
      color: isDark ? DnaColors.darkSurface : DnaColors.lightSurface,
      borderRadius: BorderRadius.circular(DnaSpacing.radiusMd),
      elevation: DnaSpacing.elevationLow,
      shadowColor: theme.cardTheme.shadowColor,
      child: InkWell(
        onTap: item.onTap,
        borderRadius: BorderRadius.circular(DnaSpacing.radiusMd),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Container(
              padding: const EdgeInsets.all(DnaSpacing.sm),
              decoration: BoxDecoration(
                gradient: DnaGradients.primarySoft(theme.brightness),
                borderRadius: BorderRadius.circular(DnaSpacing.radiusSm),
              ),
              child: ShaderMask(
                shaderCallback: DnaGradients.primaryShader,
                child: FaIcon(item.icon, size: DnaSpacing.iconLg, color: Colors.white),
              ),
            ),
            const SizedBox(height: DnaSpacing.sm),
            Text(
              item.label,
              style: theme.textTheme.labelSmall,
              textAlign: TextAlign.center,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
          ],
        ),
      ),
    );
  }
}
```

**Step 2: Verify build, commit**

```bash
git add lib/design_system/navigation/dna_more_menu.dart
git commit -m "feat(ui): add DnaMoreMenu grid+list component"
```

---

## Phase 4: Input Components

### Task 15: Create DnaTextField, DnaSearchBar, DnaSwitch

**Files:**
- Create: `lib/design_system/inputs/dna_text_field.dart`
- Create: `lib/design_system/inputs/dna_search_bar.dart`
- Create: `lib/design_system/inputs/dna_switch.dart`

**DnaTextField** — Themed text field wrapper:
- Props: `label`, `hint`, `controller`, `obscureText`, `maxLines`, `onChanged`, `prefixIcon`, `suffixIcon`
- Uses the theme's `InputDecorationTheme` automatically
- Adds gradient border on focus via `focusNode` listener

**DnaSearchBar** — Search field with debounce:
- Props: `hint`, `onChanged`, `debounceMs` (default 500)
- Leading search icon, trailing clear button (when text present)
- Built-in `Timer` for debounced callbacks

**DnaSwitch** — Toggle with label:
- Props: `label`, `value`, `onChanged`, `subtitle`
- Row layout with label on left, switch on right
- Uses theme's `switchTheme` automatically

**After creating all 3 files, verify build and commit:**

```bash
git add lib/design_system/inputs/
git commit -m "feat(ui): add DnaTextField, DnaSearchBar, DnaSwitch"
```

---

### Task 16: Create DnaDialog component

**Files:**
- Create: `lib/design_system/components/dna_dialog.dart`

**Step 1: Create the component**

Static helper for showing themed dialogs:
- `DnaDialog.confirm()` — Yes/No with title and message
- `DnaDialog.alert()` — OK only
- Uses theme's `dialogTheme` automatically
- DnaButton for actions

**Step 2: Verify build, commit**

```bash
git add lib/design_system/components/dna_dialog.dart
git commit -m "feat(ui): add DnaDialog component"
```

---

## Phase 5: Barrel Export & Legacy Bridge

### Task 17: Create barrel export and legacy compatibility shim

**Files:**
- Create: `lib/design_system/design_system.dart`
- Modify: `lib/theme/dna_theme.dart` (make it re-export new system)

**Step 1: Create barrel export**

```dart
// DNA Design System — single import for all components
library;

// Theme
export 'theme/dna_colors.dart';
export 'theme/dna_gradients.dart';
export 'theme/dna_spacing.dart';
export 'theme/dna_theme.dart';
export 'theme/dna_typography.dart';

// Components
export 'components/dna_card.dart';
export 'components/dna_button.dart';
export 'components/dna_avatar.dart';
export 'components/dna_list_tile.dart';
export 'components/dna_badge.dart';
export 'components/dna_chip.dart';
export 'components/dna_icon_button.dart';
export 'components/dna_bottom_sheet.dart';
export 'components/dna_skeleton.dart';
export 'components/dna_snack_bar.dart';
export 'components/dna_dialog.dart';

// Navigation
export 'navigation/dna_bottom_bar.dart';
export 'navigation/dna_app_bar.dart';
export 'navigation/dna_more_menu.dart';

// Inputs
export 'inputs/dna_text_field.dart';
export 'inputs/dna_search_bar.dart';
export 'inputs/dna_switch.dart';
```

**Step 2: Update legacy theme file**

Replace `lib/theme/dna_theme.dart` contents with a backward-compatible shim:

```dart
// Legacy compatibility — re-exports from new design system
// TODO: Remove after all screens are migrated to design_system imports
export '../design_system/theme/dna_colors.dart';
```

This keeps `DnaColors` available via the old import path while screens migrate.

**Step 3: Verify flutter build linux succeeds**

Run: `cd /opt/dna-messenger/dna_messenger_flutter && flutter build linux`

**Step 4: Commit**

```bash
git add lib/design_system/design_system.dart lib/theme/dna_theme.dart
git commit -m "feat(ui): add barrel export and legacy compatibility shim"
```

---

## Phase 6: Navigation Restructure

### Task 18: Rewrite home_screen.dart — drawer to bottom tabs

**Files:**
- Modify: `lib/screens/home_screen.dart` (complete rewrite)

**This is the biggest single change.** Replace the entire drawer-based navigation with bottom tab bar.

**Step 1: Rewrite home_screen.dart**

The new structure:
- `HomeScreen` → `Scaffold` with `DnaBottomBar` as `bottomNavigationBar`
- `IndexedStack` with 4 pages: Chats, Groups, Feed, MoreScreen
- Remove all drawer code (`_NavigationDrawer`, `_DrawerItem`, `_DrawerHeader`)
- Keep `_DhtStatusIndicator` (move to app bar or keep accessible)
- Update `currentTabProvider` — now 4 tabs: 0=Chats, 1=Groups, 2=Feed, 3=More
- Remove `onMenuPressed` callbacks from all screen constructors

**Key changes:**
- Screens no longer receive `onMenuPressed` — remove that parameter from `ContactsScreen`, `GroupsScreen`, `FeedScreen`, `WalletScreen`, `SettingsScreen`
- Each screen manages its own `DnaAppBar` instead of relying on drawer hamburger

**Step 2: Update each screen to remove onMenuPressed parameter**

Files to modify (remove `onMenuPressed` parameter and hamburger button):
- `lib/screens/contacts/contacts_screen.dart`
- `lib/screens/groups/groups_screen.dart`
- `lib/screens/feed/feed_screen.dart`
- `lib/screens/wallet/wallet_screen.dart`
- `lib/screens/qr/qr_scanner_screen.dart`
- `lib/screens/settings/settings_screen.dart`

Each screen: remove `final VoidCallback? onMenuPressed;` and the hamburger icon in their AppBar's `leading`.

**Step 3: Create More screen**

Create: `lib/screens/more/more_screen.dart`

This screen uses `DnaMoreMenu` component and wires up navigation to:
- Wallet → `WalletScreen`
- QR Scanner → `QrScannerScreen` (mobile only)
- Address Book → `AddressBookScreen`
- Starred → `StarredMessagesScreen`
- Blocked → `BlockedUsersScreen`
- Contact Requests → `ContactRequestsScreen`
- Settings → `SettingsScreen`
- App Lock → `AppLockSettingsScreen`
- Debug Log → (in settings)

Include profile header at top (avatar + name + fingerprint, tap → ProfileEditor).

**Step 4: Update screens barrel file**

Modify: `lib/screens/screens.dart` — add `export 'more/more_screen.dart';`

**Step 5: Verify flutter build linux succeeds**

Run: `cd /opt/dna-messenger/dna_messenger_flutter && flutter build linux`

**Step 6: Commit**

```bash
git add lib/screens/
git commit -m "feat(ui): replace drawer with bottom tab navigation + More screen"
```

---

## Phase 7: Screen-by-Screen Migration

Each task in this phase migrates one screen to use the new design system components. The pattern for each is:

1. Update imports to use `design_system/design_system.dart`
2. Replace raw Material widgets with Dna* components
3. Remove direct `DnaColors` references where theme colors suffice
4. Add `DnaCard` wrappers where appropriate
5. Use `DnaAvatar` instead of inline `CircleAvatar`
6. Use `DnaListTile` instead of raw `ListTile`
7. Verify build

### Task 19: Migrate ContactsScreen (Chats)

**Files:**
- Modify: `lib/screens/contacts/contacts_screen.dart`
- Create: `lib/screens/contacts/widgets/chat_list_item.dart` (extract from screen)

**Changes:**
- Wrap chat items in `DnaListTile` with `DnaAvatar` (with online status)
- Add `DnaSearchBar` at top (collapsible)
- Use `DnaBadge` for unread counts
- Wrap in `RefreshIndicator` for pull-to-refresh

### Task 20: Migrate ChatScreen (Conversation)

**Files:**
- Modify: `lib/screens/chat/chat_screen.dart`
- Modify: `lib/screens/chat/widgets/message_bubble.dart`

**Changes:**
- Update message bubbles with rounded corners and shadows
- Gradient accent on sent message bubbles
- Polish input bar with `DnaTextField`-style input
- Use `DnaAppBar` with contact name + avatar

### Task 21: Migrate GroupsScreen

**Files:**
- Modify: `lib/screens/groups/groups_screen.dart`

**Changes:**
- Use `DnaListTile` with `DnaAvatar` for groups
- `DnaBadge` for unread group messages
- FAB for creating new groups

### Task 22: Migrate FeedScreen

**Files:**
- Modify: `lib/screens/feed/feed_screen.dart`

**Changes:**
- `DnaCard` for feed topic items
- `DnaChip` for category filters (horizontal scroll)
- Pull-to-refresh

### Task 23: Migrate WalletScreen

**Files:**
- Modify: `lib/screens/wallet/wallet_screen.dart`

**Changes:**
- Large balance `DnaCard` with gradient header
- Token list items with crypto icons
- Action row (Send, Receive) using `DnaButton`

### Task 24: Migrate SettingsScreen

**Files:**
- Modify: `lib/screens/settings/settings_screen.dart`

**Changes:**
- Grouped settings in `DnaCard` containers
- `DnaSwitch` for toggles
- Profile card at top with `DnaAvatar`
- Theme mode toggle (dark/light) using `themeModeProvider`

### Task 25: Migrate IdentitySelectionScreen (Onboarding)

**Files:**
- Modify: `lib/screens/identity/identity_selection_screen.dart`

**Changes:**
- Gradient background
- Large centered logo
- `DnaButton` for Create/Restore actions
- Clean, welcoming layout

### Task 26: Migrate remaining screens

**Files:**
- `lib/screens/contacts/contact_requests_screen.dart`
- `lib/screens/settings/blocked_users_screen.dart`
- `lib/screens/settings/starred_messages_screen.dart`
- `lib/screens/settings/contacts_management_screen.dart`
- `lib/screens/settings/app_lock_settings_screen.dart`
- `lib/screens/profile/profile_editor_screen.dart`
- `lib/screens/lock/lock_screen.dart`

Apply design system components to each. These are smaller screens and can be done in one batch.

### Task 27: Final cleanup

**Files:**
- Delete: `lib/theme/dna_theme.dart` (legacy shim — all imports should now use design_system)
- Verify no remaining imports of old theme path
- Remove any unused `onMenuPressed` references

**Step 1: Search for old imports**

```bash
grep -r "theme/dna_theme" lib/
```

Replace any remaining with `design_system/design_system.dart` or `design_system/theme/dna_colors.dart`.

**Step 2: Verify flutter build linux succeeds**

**Step 3: Commit**

```bash
git add -A
git commit -m "feat(ui): complete design system migration, remove legacy theme"
```

---

## Phase 8: Version Bump & Documentation

### Task 28: Version bump and documentation update

**Files:**
- Modify: `dna_messenger_flutter/pubspec.yaml` — bump version
- Modify: `docs/FLUTTER_UI.md` — update to reflect new architecture
- Modify: `CLAUDE.md` — update Phase Status

**Step 1: Bump Flutter version**

In `pubspec.yaml`, bump the version (patch bump for UI redesign):
```yaml
version: 0.100.95+10195
```

**Step 2: Update FLUTTER_UI.md**

Update the executive summary and architecture sections to reflect:
- Design system architecture (`lib/design_system/`)
- Bottom tab navigation
- Dark + light theme support
- Component library

**Step 3: Update CLAUDE.md versions**

Update the Flutter version in CLAUDE.md header.

**Step 4: Verify flutter build linux succeeds**

**Step 5: Commit**

```bash
git add pubspec.yaml docs/FLUTTER_UI.md CLAUDE.md
git commit -m "feat(ui): UI redesign complete — Trust Wallet style (v0.100.95)"
```

---

## Summary

| Phase | Tasks | Description |
|-------|-------|-------------|
| 1 | Tasks 1-5 | Theme foundation (colors, gradients, typography, spacing, ThemeData) |
| 2 | Tasks 6-11 | Core components (Card, Button, Avatar, ListTile, Badge, Chip, etc.) |
| 3 | Tasks 12-14 | Navigation components (BottomBar, AppBar, MoreMenu) |
| 4 | Tasks 15-16 | Input components (TextField, SearchBar, Switch, Dialog) |
| 5 | Task 17 | Barrel export + legacy bridge |
| 6 | Task 18 | Navigation restructure (drawer → bottom tabs) |
| 7 | Tasks 19-27 | Screen-by-screen migration (9 tasks) |
| 8 | Task 28 | Version bump + documentation |

**Total: 28 tasks across 8 phases**

**Build verification:** Every phase ends with `flutter build linux` to ensure nothing breaks.

**Risk mitigation:** The legacy shim (Task 17) ensures existing screens keep working during migration. Each screen migrates independently — no big-bang rewrite.
