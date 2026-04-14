// DNA Connect internal custom_lint rules.
//
// This package is wired into the Flutter app via a path dev_dependency in
// messenger/dna_messenger_flutter/pubspec.yaml and registered as an analyzer
// plugin in messenger/dna_messenger_flutter/analysis_options.yaml.
//
// STATUS: ENABLED — enforcing `avoid_dna_log_primitives` across `lib/`.
// The [AvoidDnaLogPrimitives] rule walks MethodInvocation nodes and reports
// a diagnostic error for every `debugPrint(`, `print(`, and `developer.log(`
// call site in Dart files under `lib/`, except the exclusion list below
// (generated localization, build-artifact `.g.dart` / `.freezed.dart`, and
// anything outside `lib/` — tests, tools, bin). Run the enforcement via
// `dart run custom_lint` (it is NOT triggered by `flutter analyze`).

import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/error/error.dart'
    hide
        // ignore: undefined_hidden_name, needed to support lower analyzer versions
        LintCode;
import 'package:analyzer/error/listener.dart';
import 'package:custom_lint_builder/custom_lint_builder.dart';

/// custom_lint plugin entry point.
PluginBase createPlugin() => _DnaLintsPlugin();

class _DnaLintsPlugin extends PluginBase {
  @override
  List<LintRule> getLintRules(CustomLintConfigs configs) => [
        AvoidDnaLogPrimitives(),
      ];
}

/// Rule that forbids raw logging primitives (`debugPrint`, `print`,
/// `developer.log`) in `lib/`. DnaLogger (`lib/utils/logger.dart`) is the
/// project-sanctioned replacement per CLAUDE.md "ONE logging system" rule.
///
/// ENABLED by Plan 04-03 Task 2 after the sweep of the 14 historical sites
/// completed in plans 04-02 and 04-03 Task 1. From this point forward any
/// new call to one of the forbidden primitives in `lib/` is a
/// `dart run custom_lint` hard error.
class AvoidDnaLogPrimitives extends DartLintRule {
  // Phase 4 anti-regression gate is live.
  static const bool _enabled = true;

  const AvoidDnaLogPrimitives()
      : super(
          code: const LintCode(
            name: 'avoid_dna_log_primitives',
            problemMessage:
                'Use DnaLogger (lib/utils/logger.dart) instead of '
                'debugPrint/print/developer.log in lib/.',
            errorSeverity: ErrorSeverity.ERROR,
          ),
        );

  /// Returns `true` when [filePath] is a Dart source file under `lib/`
  /// that should be checked by this rule. Excludes:
  ///   - generated localization (`lib/l10n/**`)
  ///   - build-artifact files (`*.g.dart`, `*.freezed.dart`)
  ///   - anything outside `lib/` (tests, tools, bin, generated entrypoints)
  static bool _shouldCheck(String filePath) {
    // Normalize to forward slashes so the checks work on every platform the
    // analyzer runs on (the CustomLintResolver.path is OS-native).
    final normalized = filePath.replaceAll(r'\', '/');

    // Only Dart sources inside a `lib/` directory are checked.
    if (!normalized.contains('/lib/')) {
      return false;
    }

    // Generated / build-artifact files are exempt — we don't own them.
    if (normalized.endsWith('.g.dart') ||
        normalized.endsWith('.freezed.dart')) {
      return false;
    }

    // Generated localization bundle — exempt per D-11.
    if (normalized.contains('/lib/l10n/')) {
      return false;
    }

    return true;
  }

  @override
  void run(
    CustomLintResolver resolver,
    ErrorReporter reporter,
    CustomLintContext context,
  ) {
    if (!_enabled) {
      return;
    }

    if (!_shouldCheck(resolver.path)) {
      return;
    }

    context.registry.addMethodInvocation((node) {
      final methodName = node.methodName.name;

      // Top-level `print(...)` (dart:core). Unqualified — the receiver
      // (`node.target`) must be null, otherwise it's some unrelated method
      // that happens to share the name (e.g. `someLogger.print(...)`).
      if (methodName == 'print') {
        if (node.target == null) {
          reporter.atNode(node, code);
        }
        return;
      }

      // `developer.log(...)` — the canonical form uses a plain `developer`
      // prefix from `import 'dart:developer' as developer;`. Aliased
      // imports such as `as dev` are accepted per T-04-10 (no occurrences
      // in lib/ today; aliased-prefix resolution via the element model is
      // deferred to a future hardening iteration).
      if (methodName == 'log') {
        final target = node.target;
        if (target != null && target.toSource() == 'developer') {
          reporter.atNode(node, code);
        }
      }
    });

    // `debugPrint` is NOT a function in the analyzer sense — it's a top-level
    // field of type `DebugPrintCallback` declared in
    // `package:flutter/foundation.dart`:
    //
    //   DebugPrintCallback debugPrint = debugPrintThrottled;
    //
    // Calling `debugPrint('x')` therefore parses as a
    // [FunctionExpressionInvocation] (the function object is the `function`
    // subexpression, which is a [SimpleIdentifier] naming the variable).
    // [MethodInvocation] does NOT cover it, so we register a second visitor.
    context.registry.addFunctionExpressionInvocation((node) {
      final function = node.function;
      if (function is SimpleIdentifier && function.name == 'debugPrint') {
        reporter.atNode(node, code);
      }
    });
  }
}
